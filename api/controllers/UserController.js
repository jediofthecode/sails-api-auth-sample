/**
 * UserController
 *
 * @description :: Controller for User resource, currently used for api access auth, can expand upon need
 * @help        :: See http://sailsjs.org/#!/documentation/concepts/Controllers
 */

var bcrypt = require('bcrypt');
var moment = require('moment');
var sha1 = require('sha1');

module.exports = {
	// private function to generate random string
	// used to generate random access token
	__genString: function(len) {
		var text = "";
		var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

		for( var i=0; i < len; i++ )
			text += possible.charAt(Math.floor(Math.random() * possible.length));

		return text;
	},
	
	// controller auth method, accepts username and password, and then generates
	// random access token, and assign expiry(currently 30 days)
	// gracefully breaks(returns relevant status codes and error msgs)
	auth: function(req, res) {
		var self = this;

		if (req.body) {
			if (!req.body.username || !req.body.password)
				return res.status(400).json({error: 'Missing parameters', status: 400});

			//return res.status(200).json(req.body);
			User.findOne({username: req.body.username}).exec(function(err, user) {
				if (err || !user)
					return res.status(404).json({error: 'User not found', status: 404});

				bcrypt.compare(req.body.password, user.password, function(err, resp) {
					var now = moment().utc();

					if (resp == false)
						return res.status(401).json({error: 'Incorrect Password', status: 401});
	
					AuthToken.find({ expires: { '>': new Date(now.toISOString())}, user: user.id}).populate('user').exec(function(err, tokens) {
						if (tokens.length < 1) {
							var __accessToken = self.__genString(32); // generate 64 char access token
							__accessToken = sha1(user.username + user.email + now.toISOString + __accessToken);
							AuthToken.create({
								user: user.id,
								expires: now.add(1, 'months').toISOString(),
								token: __accessToken
							}).exec(function(err, newToken) {
								if (err)
									console.log(err);

								var __token = newToken;
								__token.user = user;
								delete __token.user.password;
								delete __token.user.id;
								delete __token.id;

								return res.status(200).json(__token);
							});
						} else {
							// get latest token, sanitize it for output, and then return it
							var __token = tokens[0];
							delete __token.user.password;
							delete __token.user.id;
							delete __token.id;
							return res.status(200).json(__token);
						}
					});
				});
				//return res.status(200).json({access_token: self.__genString(64)});
			});
		} else {
			return res.status(400).json({error: 'Please enter required auth credentials', status: 400});
		}
	}
};

