// api access authentication policy
// version 1.0 
// patrick johnson
// for internal use only

var moment = require('moment');

module.exports = function apiAuth (req, res, next) {
	//console.log(req.headers);
	
	if (!req.headers.authorization)
		return res.status(403).json({error: 'Must send auth headers', code: 403});

	var authInfo = req.headers.authorization.split(" : "),
		now = moment().utc();

	if (authInfo.length !== 2)
		return res.status(400).json({error: 'Invalid authorization string', code: 400});
	
	var username = authInfo[0],
		accessToken = authInfo[1];
	
	User.findOne({username: username}).exec(function(err, user) {
		if (!user)
			return res.status(403).json({error: 'User ' + username + ' does not exist', code: 400});

		AuthToken.findOne({user: user.id, expires: {'>': new Date(now.toISOString()) }}).exec(function(err, authToken) {
			if (!authToken)
				return res.status(400).json({error: 'No valid auth token exists for user ' + user.username, code: 400});

			if (accessToken == authToken.token)
				next()
			else
				return res.status(403).json({error: 'Invalid auth token', code: 403});
		});
	});

};
