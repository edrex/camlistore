/*
Copyright 2014 The Camlistore Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package app helps with configuring and starting server applications
// from Camlistore.
package app

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"camlistore.org/pkg/auth"
	camhttputil "camlistore.org/pkg/httputil"
	"go4.org/jsonconfig"
)

// Handler acts as a reverse proxy for a server application started by
// Camlistore. It can also serve some extra JSON configuration to the app.
type Handler struct {
	name    string            // Name of the app's program.
	envVars map[string]string // Variables set in the app's process environment. See doc/app-environment.txt.

	auth      auth.AuthMode  // Used for basic HTTP authenticating against the app requests.
	appConfig jsonconfig.Obj // Additional parameters the app can request, or nil.

	prefix     string                 // Prefix to strip from requests before proxying them to the app.
	proxy      *httputil.ReverseProxy // For redirecting requests to the app.
	backendURL string                 // URL that we proxy to (i.e. base URL of the app).

	process *os.Process // The app's Pid. To send it signals on restart, etc.
}

func (a *Handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if camhttputil.PathSuffix(req) == "config.json" {
		if a.auth.AllowedAccess(req)&auth.OpGet == auth.OpGet {
			camhttputil.ReturnJSON(rw, a.appConfig)
		} else {
			auth.SendUnauthorized(rw, req)
		}
		return
	}
	if a.proxy == nil {
		http.Error(rw, "no proxy for the app", 500)
		return
	}
	req.URL.Path = strings.TrimPrefix(req.URL.Path, a.prefix)
	a.proxy.ServeHTTP(rw, req)
}

func randPort() (int, error) {
	var port int
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return port, err
	}
	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return port, fmt.Errorf("could not listen to find random port: %v", err)
	}
	randAddr := listener.Addr().(*net.TCPAddr)
	if err := listener.Close(); err != nil {
		return port, fmt.Errorf("could not close random listener: %v", err)
	}
	return randAddr.Port, nil
}

// Given a string of the form "host", "host:port", or "[ipv6::address]:port",
// return true if the string includes a port.
func hasPort(s string) bool { return strings.LastIndex(s, ":") > strings.LastIndex(s, "]") }

var portMap = map[string]string{
	"http":  "80",
	"https": "443",
}

// canonicalAddr returns url.Host but always with a ":port" suffix
func canonicalAddr(url *url.URL) string {
	addr := url.Host
	if !hasPort(addr) {
		return addr + ":" + portMap[url.Scheme]
	}
	return addr
}

// listenPort returns as a string the port in listenAddr, if listenAddr is not
// empty, otherwise a randomly selected port.
func listenPort(listenAddr string) (string, error) {
	if listenAddr != "" {
		portIdx := strings.LastIndex(listenAddr, ":") + 1
		if portIdx <= 0 || portIdx >= len(listenAddr) {
			return "", errors.New("invalid listen addr, no port found")
		}
		return listenAddr[portIdx:], nil
	}
	port, err := randPort()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d", port), nil
}

// listenAndbackendURL returns the listening address that the app should use,
// and the backend URL that the app handler should proxy to for this app.
// listenAddr is defined:
// 1) As listen if not empty
// 2) Or derived from backend, adding a canonical port if necessary
// 3) Or as the host in apiHost + random port
// backendURL is defined:
// 1) As backend if not empty
// 2) As apiHost scheme + apiHost host + port in listen if exists
// 3) As apiHost scheme + apiHost host + random port
func listenAndBaseURL(listen, backend, apiHost string) (listenAddr, backendURL string, err error) {
	if listen != "" {
		listenAddr = listen
	}
	if backend != "" {
		baseURL, err := url.Parse(backend)
		if err != nil {
			return "", "", fmt.Errorf("invalid baseURL %q: %v", backend, err)
		}
		backendURL = backend
		if listenAddr == "" {
			listenAddr = canonicalAddr(baseURL)
		}
		return listenAddr, backendURL, err
	}
	apiURL, err := url.Parse(apiHost)
	if err != nil {
		return "", "", fmt.Errorf("invalid apiHost %q: %v", apiHost, err)
	}
	port, err := listenPort(listenAddr)
	if err != nil {
		return "", "", err
	}
	var hostPort string
	if hasPort(apiURL.Host) {
		hostPort = apiURL.Host[:strings.LastIndex(apiURL.Host, ":")] + ":" + port
	} else {
		hostPort = apiURL.Host + ":" + port
	}
	if listenAddr == "" {
		listenAddr = hostPort
	}
	backendURL = apiURL.Scheme + "://" + hostPort
	return listenAddr, backendURL, err
}

// NewHandler returns a Handler that proxies requests to an app. Start() on the
// Handler starts the app.
// The apiHost must end in a slash and is the camlistored API server for the app
// process to hit.
// The appHandlerPrefix is the URL path prefix on apiHost where the app is mounted.
// It must end in a slash, and be at minimum "/".
// The conf object has the following members, related to the vars described in
// doc/app-environment.txt:
// "program", string, required. File name of the app's program executable. Either
// an absolute path, or the name of a file located in CAMLI_APP_BINDIR or in PATH.
// "backendURL", string, optional. Automatic if absent. It sets CAMLI_APP_BACKEND_URL.
// "listen", string, optional. Automatic if absent. It sets CAMLI_APP_LISTEN.
// "appConfig", object, optional. Additional configuration that the app can request from Camlistore.
func NewHandler(conf jsonconfig.Obj, apiHost, appHandlerPrefix string) (*Handler, error) {
	name := conf.RequiredString("program")
	backend := conf.OptionalString("backendURL", "")
	listen := conf.OptionalString("listen", "")
	appConfig := conf.OptionalObject("appConfig")
	// TODO(mpl): add an auth token in the extra config of the dev server config,
	// that the hello app can use to setup a status handler than only responds
	// to requests with that token.
	if err := conf.Validate(); err != nil {
		return nil, err
	}

	if apiHost == "" {
		return nil, fmt.Errorf("app: could not initialize Handler for %q: Camlistore apiHost is unknown", name)
	}
	if appHandlerPrefix == "" {
		return nil, fmt.Errorf("app: could not initialize Handler for %q: empty appHandlerPrefix", name)
	}

	listenAddr, backendURL, err := listenAndBaseURL(listen, backend, apiHost)
	if err != nil {
		return nil, err
	}
	proxyURL, err := url.Parse(backendURL)
	if err != nil {
		return nil, fmt.Errorf("could not parse backendURL %q: %v", backendURL, err)
	}

	username, password := auth.RandToken(20), auth.RandToken(20)
	camliAuth := username + ":" + password
	basicAuth := auth.NewBasicAuth(username, password)
	envVars := map[string]string{
		"CAMLI_API_HOST":        apiHost,
		"CAMLI_AUTH":            camliAuth,
		"CAMLI_APP_BACKEND_URL": backendURL,
		"CAMLI_APP_LISTEN":      listenAddr,
	}
	if appConfig != nil {
		envVars["CAMLI_APP_CONFIG_URL"] = apiHost + strings.TrimPrefix(appHandlerPrefix, "/") + "config.json"
	}

	return &Handler{
		name:       name,
		envVars:    envVars,
		auth:       basicAuth,
		appConfig:  appConfig,
		prefix:     appHandlerPrefix,
		proxy:      httputil.NewSingleHostReverseProxy(proxyURL),
		backendURL: backendURL,
	}, nil
}

func (a *Handler) Start() error {
	name := a.name
	if name == "" {
		return fmt.Errorf("invalid app name: %q", name)
	}
	var binPath string
	var err error
	if e := os.Getenv("CAMLI_APP_BINDIR"); e != "" {
		binPath, err = exec.LookPath(filepath.Join(e, name))
		if err != nil {
			log.Printf("%q executable not found in %q", name, e)
		}
	}
	if binPath == "" || err != nil {
		binPath, err = exec.LookPath(name)
		if err != nil {
			return fmt.Errorf("%q executable not found in PATH.", name)
		}
	}

	cmd := exec.Command(binPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// TODO(mpl): extract Env methods from dev/devcam/env.go to a util pkg and use them here.
	newVars := make(map[string]string, len(a.envVars))
	for k, v := range a.envVars {
		newVars[k+"="] = v
	}
	env := os.Environ()
	for pos, oldkv := range env {
		for k, newVal := range newVars {
			if strings.HasPrefix(oldkv, k) {
				env[pos] = k + newVal
				delete(newVars, k)
				break
			}
		}
	}
	for k, v := range newVars {
		env = append(env, k+v)
	}
	cmd.Env = env
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("could not start app %v: %v", name, err)
	}
	a.process = cmd.Process
	return nil
}

// ProgramName returns the name of the app's binary. It may be a file name in
// CAMLI_APP_BINDIR or PATH, or an absolute path.
func (a *Handler) ProgramName() string {
	return a.name
}

// AuthMode returns the app handler's auth mode, which is also the auth that the
// app's client will be configured with. This mode should be registered with
// the server's auth modes, for the app to have access to the server's resources.
func (a *Handler) AuthMode() auth.AuthMode {
	return a.auth
}

// AppConfig returns the optional configuration parameters object that the app
// can request from the app handler. It can be nil.
func (a *Handler) AppConfig() map[string]interface{} {
	return a.appConfig
}

// BackendURL returns the appBackendURL that the app handler will proxy to.
func (a *Handler) BackendURL() string {
	return a.backendURL
}

var errProcessTookTooLong = errors.New("proccess took too long to quit")

// Quit sends the app's process a SIGINT, and waits up to 5 seconds for it
// to exit, returning an error if it doesn't.
func (a *Handler) Quit() error {
	err := a.process.Signal(os.Interrupt)
	if err != nil {
		return err
	}

	c := make(chan error)
	go func() {
		_, err := a.process.Wait()
		c <- err
	}()
	select {
	case err = <-c:
	case <-time.After(5 * time.Second):
		// TODO Do we want to SIGKILL here or just leave the app alone?
		err = errProcessTookTooLong
	}
	return err
}
