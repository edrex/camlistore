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

goog.provide('cam.LocationDetail');

goog.require('cam.Map');
goog.require('cam.Thumber');

// Renders the detail view for locations.
cam.LocationDetail = React.createClass({
	displayName: 'LocationDetail',

	IMG_MARGIN: 20,
	PIGGY_WIDTH: 88,
	PIGGY_HEIGHT: 62,

	propTypes: {
		backwardPiggy: React.PropTypes.bool.isRequired,
		permanodeMeta: React.PropTypes.object,
		resolvedMeta: React.PropTypes.object.isRequired
	},

  render: function() {
    var marker = {
      point: [
        this.props.resolvedMeta.location.lat,
        this.props.resolvedMeta.location.long
      ],
      thumb: cam.Thumber.fromImageMeta(this.props.resolvedMeta)
    };
    return cam.Map({
      markers:[marker],
      width: this.props.width,
      height: this.props.height
    });
  }
});

cam.LocationDetail.getAspect = function(blobref, searchSession) {
if (!blobref) {
return null;
}

	var rm = searchSession.getResolvedMeta(blobref);
	var pm = searchSession.getMeta(blobref);

	if (!pm) {
		return null;
	}

	if (pm.camliType != 'permanode') {
		pm = null;
	}

	if (rm && rm.location) {
		return {
			fragment: 'location',
			title: 'Location',
			createContent: function(size, backwardPiggy) {
				return cam.LocationDetail({
					backwardPiggy: backwardPiggy,
					permanodeMeta: pm,
					resolvedMeta: rm,
					height: size.height,
					width: size.width
				});
			},
		};
	} else {
		return null;
	}
};
