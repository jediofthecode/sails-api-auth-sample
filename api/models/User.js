/**
* User.js
*
* @description :: TODO: You might write a short summary of how this model works and what it represents here.
* @docs        :: http://sailsjs.org/#!documentation/models
*/

var bcrypt = require('bcrypt');

module.exports = {
	attributes: {
		username: {
			type: 'string',
			required: true,
			unique: true
		},
		password: {
			type: 'string',
			required: true
		},
		email: {
			type: 'email',
			required: true
		},
		first_name: {
			type: 'string',
			required: true
		},
		last_name: {
			type: 'string',
			required: true
		}
	},

	// hash password before creation
	beforeCreate: function(values, cb) {
		bcrypt.genSalt(10, function(err, salt) {
			bcrypt.hash(values.password, salt, function(err, hash) {
				if (err)
					return false;

				values.password = hash;
				cb();
			});
		});
	}
};
