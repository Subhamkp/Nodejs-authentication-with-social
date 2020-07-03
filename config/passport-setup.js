require('dotenv').config();
const passport = require('passport');
const crypto = require('crypto');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
const FacebookStrategy = require('passport-facebook');
const LinkedInStrategy = require('passport-linkedin-oauth2').Strategy;
const { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, FACEBOOK_CLIENT_ID,
	FACEBOOK_CLIENT_SECRET, LINKEDIN_CLIENT_ID, LINKEDIN_CLIENT_SECRET } = process.env;

const User = require('../models/user');

//Takes user and grab some info from it to stuff in cookie and send to browser
passport.serializeUser((user, done) => {
	// console.log("SerializedUser\n "+ user);
	done(null, user.id);
});

// when browser sends cookie then find the user and pass the user to next stage
passport.deserializeUser((id, done) => {
	User.findById(id).then((user) => {
		// console.log("DeserializedUser\n "+ user);
		done(null, user);
	}).catch((err) => {
		done(err, user);
	});
});

passport.use(new LocalStrategy({
	usernameField: 'email',
	passwordField: 'password'
}, (email, password, done) => {

	User.findOne({ email: email }, function (err, user) {
		console.log("Email finded\n" + user);
		if (err) {
			done(err);
		}

		if (!user) {
			return done(null, false, { message: 'Unknown User, Kindly register first' });
		}

		User.comparePassword(password, user.password, function (err, isMatch) {
			if (err) throw err;
			if (isMatch) {
				console.log("Is matched USER\n" + user);
				return done(null, user);
			} else {
				return done(null, false, { message: 'Invalid password' });
			}
		});
	});
}));

// function to create random string
function randString() {
	var token = crypto.randomBytes(16).toString('hex');
	return token;
}

var google_strategy = new GoogleStrategy({
	//options for the google strategy
	callbackURL: '/auth/google/redirect',
	clientID: GOOGLE_CLIENT_ID,
	clientSecret: GOOGLE_CLIENT_SECRET
}, (accessToken, refreshToken, profile, done) => {

	console.log(JSON.stringify(profile));

	var emailExists = false;
	if (profile.emails && profile.emails[0] && profile.emails[0].value) {
		emailExists = true;
	}

	User.findOne({ email: (emailExists ? profile.emails[0].value : null) }).then((user) => {
		if (user) {
			user.googleId = profile.id;
			if (!user.gender) {
				user.gender = profile.gender;
			}

			if (!user.DOB) {
				user.DOB = profile._json.birthday;
			}

			if (!user.thumbnail || user.thumbnail == 'default.png') {
				user.thumbnail = profile._json.picture;
			}
			user.save().then((currentUser) => {
				console.log('user is : ' + currentUser);
				done(null, currentUser);
			});
		} else {
			User.findOne({ googleId: profile.id }).then((user) => {
				if (user) {
					if (!user.gender) {
						user.gender = profile.gender;
					}
					if (!user.DOB) {
						user.DOB = profile._json.birthday;
					}
					if (!user.thumbnail || user.thumbnail == 'default.png') {
						user.thumbnail = profile._json.picture;
					}
					user.save().then((currentUser) => {
						console.log('user is : ' + currentUser);
						done(null, currentUser);
					})
				} else {
					new User({
						googleId: profile.id,
						email: (emailExists ? profile.emails[0].value : randString()),
						emailPresent: (emailExists ? true : false),
						verifiedEmail: emailExists,
						DOB: profile._json.birthday,
						name: profile.displayName,
						thumbnail: profile._json.picture,
						gender: profile.gender
					}).save().then((newUser) => {
						// console.log('new user created:'+newUser);
						done(null, newUser);
					});
				}
			})
		}
	}).catch((err) => {
		throw new Error("Something Went Wrong " + err);
	});
});

var facebook_strategy = new FacebookStrategy({
	//options for facebook strategy
	clientID: FACEBOOK_CLIENT_ID,
	clientSecret: FACEBOOK_CLIENT_SECRET,
	callbackURL: '/auth/facebook/redirect',
	scope: ['r_emailaddress', 'r_liteprofile'],
	state: true
}, (accessToken, refreshToken, profile, done) => {

	console.log(profile);

	var emailExists = false;
	if (profile._json && profile._json.email) {
		emailExists = true;
	}
	User.findOne({ email: (emailExists ? profile._json.email : null) }).then((result) => {
		if (result) {
			result.facebookId = profile.id;
			if (!result.gender) {
				result.gender = profile.gender;
			}
			if (!result.thumbnail || result.thumbnail == 'default.png') {
				result.thumbnail = `http://graph.facebook.com/${profile.id}/picture?type=large&width=720&height=720`;
			}
			result.save().then((currentUser) => {
				console.log('user is : ' + currentUser);
				done(null, currentUser);
			});
		} else {
			User.findOne({ facebookId: profile.id }).then((record) => {
				if (record) {
					if (!record.gender) {
						record.gender = profile.gender;
					}
					if (!record.thumbnail || record.thumbnail == 'default.png') {
						record.thumbnail = `http://graph.facebook.com/${profile.id}/picture?type=large&width=400&height=400`;
					}
					record.save().then((currentUser) => {
						// console.log('user is : '+currentUser);
						done(null, currentUser);
					})
				} else {
					new User({
						facebookId: profile.id,
						email: (emailExists ? profile._json.email : randString()),
						emailPresent: (emailExists ? true : false),
						name: profile.displayName,
						thumbnail: `http://graph.facebook.com/${profile.id}/picture?type=large&width=720&height=720`,
						gender: profile.gender,
						verifiedEmail: emailExists,
					}).save().then((newUser) => {
						// console.log('new user created:'+newUser);
						done(null, newUser);
					});
				}
			});
		}
	});
});


var linkedin_Strategy = passport.use(new LinkedInStrategy({
	clientID: LINKEDIN_CLIENT_ID,
	clientSecret: LINKEDIN_CLIENT_SECRET,
	callbackURL: "/auth/linkedin/redirect",
	scope: ['r_emailaddress', 'r_liteprofile']
},
	function (token, tokenSecret, profile, done) {
		var emailExists = false;
		if (profile.emails && profile.emails[0].value) {
			emailExists = true;
		}
		User.findOne({ email: (emailExists ? profile.emails[0].value : null) }).then((result) => {
			if (result) {
				result.linkedinId = profile.id;
				if (!result.thumbnail || result.thumbnail == 'default.png') {
					result.thumbnail = profile.photos[2].value;
				}
				result.save().then((currentUser) => {
					console.log('user is : ' + currentUser);
					done(null, currentUser);
				});
			} else {
				User.findOne({ linkedinId: profile.id }).then((record) => {
					if (record) {
						if (!record.thumbnail || record.thumbnail == 'default.png') {
							record.thumbnail = profile.photos[2].value;
						}
						record.save().then((currentUser) => {
							done(null, currentUser);
						})
					} else {
						new User({
							linkedinId: profile.id,
							email: (emailExists ? profile.emails[0].value : randString()),
							emailPresent: (emailExists ? true : false),
							name: profile.displayName,
							thumbnail: profile.photos[2].value,
							verifiedEmail: emailExists,
						}).save().then((newUser) => {
							// console.log('new user created:'+newUser);
							done(null, newUser);
						});
					}
				});
			}
		});
	}
));

// To run in corporate in ubuntu
// set env in windows by: set https_proxy=http://username:passport@proxy:port
// set env in ubuntu by export command
// const HttpsProxyAgent = require('https-proxy-agent');
//
// if (process.env['https_proxy']) {
//   var httpsProxyAgent = new HttpsProxyAgent(process.env['https_proxy']);
//   facebook_strategy._oauth2.setAgent(httpsProxyAgent);
// 	google_strategy._oauth2.setAgent(httpsProxyAgent);
// }

passport.use("linkedin_Strategy", linkedin_Strategy);
passport.use(facebook_strategy);
passport.use(google_strategy);
