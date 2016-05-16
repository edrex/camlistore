/*
Copyright 2016 The Camlistore Authors

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

goog.provide('cam.Map');

// React wrapper around a Leaftet map.
cam.Map = React.createClass({
  displayName: 'Map',
  getDefaultProps: function(){
    return {
      markers: [],
      width: 0,
      height: 0,
      thumbSize: 32
    }
  },
  render: function(){
    return React.DOM.div({
      className: 'cam-location-detail--map',
      style: this.getStyle_()
    });
  },
  componentDidMount: function() {
    // todo: this should be on set props
    var markers = L.featureGroup(this.props.markers.map(function(m){
      var markerOpts = {};
      if (m.thumb) {
        markerOpts.icon = L.icon({
          iconUrl: m.thumb.getSrc(this.props.thumbSize)
        })
      }
      return L.marker(m.point, markerOpts);
    }, this));

    // instantiate the Leaflet map object
    map = L.map(this.getDOMNode(), {});
    L.tileLayer('http://{s}.tile.osm.org/{z}/{x}/{y}.png', {
      attribution: '&copy; <a href="http://osm.org/copyright">OpenStreetMap</a> contributors'
    }).addTo(map);
    markers.addTo(map);
    map.fitBounds(markers.getBounds(), {});
  },
	getStyle_: function() {
		return {
			width: this.props.width,
			height: this.props.height
		}
	},
})


