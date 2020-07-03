require('dotenv').config();
const router = require('express').Router();
const async = require('async');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
var User = require('../models/user');
const { DOMAIN_EMAIL, DOMAIN_PASSWORD } = process.env;

const authCheck = (req, res, next) => {
	// if (!req.user) {
	// 	req.flash('error_msg', 'You are not logged in, Please login to access profile');
	// 	res.redirect('/auth/login');
	// } else {
	next();
	// }
}

router.get('/', authCheck, (req, res) => {
	res.render('profile', { user: req.user });
});

// Register User
router.get('/verifyemail', authCheck, function (req, res) {
	if (req.user.verifiedEmail) {
		req.flash('success_msg', 'Your email has been already verified');
		res.redirect('/profile');
	} else {

		async.waterfall([
			function (done) {
				crypto.randomBytes(30, function (err, buf) {
					var token = buf.toString('hex');
					done(err, token);
				});
			},
			function (token, done) {
				User.findOne({ email: req.user.email }, function (err, user) {
					if (!user) {
						req.flash('error', 'No account with that email address exists.');
						return res.redirect('/');
					}
					user.verifyEmailToken = token;
					user.verifyEmailExpires = Date.now() + 3600000; // 1 hour


					user.save(function (err) {
						done(err, token, user);
					});
				});
			},
			function (token, user, done) {
				var transporter = nodemailer.createTransport({
					service: 'gmail',
					auth: {
						user: DOMAIN_EMAIL,
						pass: DOMAIN_PASSWORD
					}
				});
				var mailOptions = {
					to: user.email,
					from: 'DemoLogin',
					subject: 'Email Verification',
					text: 'You are receiving this because you (or someone else) have requested to verify the email of your account.\n\n' +
						'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
						'https://' + req.headers.host + '/profile/verifyemail/' + token + '\n\n' +
						'If you d not request this, please ignore this email\n'
				};
				console.log('Email Verify token ' + token);
				transporter.sendMail(mailOptions, function (err, info) {
					if (err) {
						req.flash('error_msg', 'Unable to send email ' + err);
						return res.redirect('/');
					} else {
						console.log('Email sent: \n' + info.response);
						req.flash('success_msg', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
						done(err, 'done');
					}
				});
			}
		], function (err) {
			if (err) return next(err);
			res.redirect('/profile');
		});
	}
});

router.get('/verifyemail/:token', function (req, res) {
	async.waterfall([
		function (done) {
			User.findOne({ verifyEmailToken: req.params.token, verifyEmailExpires: { $gt: Date.now() } }, function (err, user) {
				if (!user) {
					req.flash('error', 'Verify Email token is invalid or has expired.');
					return res.redirect('back');
				}
				user.verifiedEmail = true;
				user.verifyEmailToken = undefined;
				user.verifyEmailExpires = undefined;

				user.save(function (err) {
					req.login(user, function (err) {
						done(err, user);
					});
				});
			});
		},
		function (user, done) {
			var transporter = nodemailer.createTransport({
				service: 'gmail',
				auth: {
					user: DOMAIN_EMAIL,
					pass: DOMAIN_PASSWORD
				}
			});
			var mailOptions = {
				to: user.email,
				from: 'DemoLogin',
				subject: 'Your Email has been verified',
				text: 'Hello,\n\n' +
					'This is a confirmation that your account having Email ' + user.email + ' has just been verified.\n'
			};
			transporter.sendMail(mailOptions, function (err, info) {
				if (err) {
					req.flash('error_msg', 'Unable to send email ' + err);
				} else {
					console.log('Email sent: \n' + info.response);
					req.flash('success_msg', 'Success! Your Email has been verified.');
				}
				done(err);
			});
		}
	], function (err) {
		res.redirect('/profile');
	});
});

module.exports = router;
