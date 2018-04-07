const router =require("express").Router();
const passport =require('passport');
const async = require('async');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const keys=require('../config/keys');
var User = require('../models/user');

// Register
router.get('/register', function(req, res){
	res.render('register',{errors:''});
});

// Register User
router.post('/register', function(req, res){
	var name = req.body.name;
	var email = req.body.email;
	var DOB = req.body.DOB;
	var mobile = req.body.mobile;
	var password = req.body.password;
	var password2 = req.body.password2;

	// Validation
	req.checkBody('name', 'Name is required').notEmpty();
	req.checkBody('email', 'Email is required').notEmpty();
	req.checkBody('DOB', 'DOB is required').notEmpty();
	req.checkBody('mobile', 'Phone number is required.').notEmpty();
	req.checkBody('password', 'Password is required').notEmpty();

	req.checkBody('email', 'Email is not valid').isEmail();
	req.checkBody('DOB', 'Enter a valid date of birth').isBefore();
	req.checkBody('mobile', 'Enter a valid phone number.').isMobilePhone('any');
	req.checkBody('password2', 'Passwords do not match').equals(req.body.password);

	var errors = req.validationErrors();

	if(errors){
		console.log('errors '+errors);
		res.render('register', {errors:errors });
	} else {
		User.findOne({email:email},function(err,user){
				if(err) req.flash('error_msg', err);

		    if(!user){
						var newUser = new User({
							name: name,
							email:email,
							DOB:DOB,
							mobile:mobile,
							password: password,
							setEmail:true,
							thumbnail:'default.png'
						});

						newUser.save(function(err, user){
							if(err){
								req.flash('error','Error in creating user '+ err);
								console.log("Error in creating user "+ err);
								res.redirect('/auth/register');
							}else{
							console.log("User is "+ user);
							req.login(user, (err) => {
									if (err) {
										throw err;
									}
									else{
										req.flash('success_msg','You have successfully registered, Please verify your email');
										res.redirect('/profile');
									}
								})
							}
						});
					}
					else{
						req.flash('error_msg', 'Email is Unique');
						res.redirect('/auth/register');
					}
			});
		}
});

// auth Login
router.get('/login',(req,res)=>{
  res.render('login',{user:req.user});
});

router.post('/login',
  passport.authenticate('local',
	 {successRedirect:'/profile',
	 failureRedirect:'/auth/login',
	 failureFlash: true,
	 successFlash: 'Welcome!'
 })
);

//auth Logout
router.get('/logout',(req,res)=>{
    //handle with passsport
    req.logout();
		req.flash('success_msg','You are successfully Logged out');
    res.redirect('/');
});

//auth forgot
router.get('/forgot', function(req, res) {
  res.render('forgot', { user: req.user });
});

router.post('/forgot', function(req, res, next) {
  async.waterfall([
    function(done) {
      crypto.randomBytes(30, function(err, buf) {
        var token = buf.toString('hex');
        done(err, token);
      });
    },
    function(token, done) {
      User.findOne({ email: req.body.email }, function(err, user) {
        if (!user) {
          req.flash('error', 'No account with that email address exists.');
          return res.redirect('/auth/forgot');
        }
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

        user.save(function(err) {
          done(err, token, user);
        });
      });
    },
    function(token, user, done) {
			var transporter = nodemailer.createTransport({
			  service: 'gmail',
			  auth: {
			    user: keys.mail.email,
			    pass: keys.mail.password
			  }
			});
      var mailOptions = {
        to: user.email,
        from: '4Times',
        subject: 'Password Reset',
        text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
          'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
          'https://' + req.headers.host + '/auth/reset/' + token + '\n\n' +
          'If you d not request this, please ignore this email and your password will remain unchanged.\n'
      };
			console.log('Reset token '+token);
      transporter.sendMail(mailOptions, function(err, info) {
				if (err) {
					req.flash('error_msg', 'Unable to send email '+err);
					return res.redirect('/auth/forgot');
				} else {
						console.log('Email sent: \n' + info.response);
        		req.flash('success_msg', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
        		done(err, 'done');
				}
      });
    }
  ], function(err) {
    if (err) return next(err);
    res.redirect('/auth/forgot');
  });
});

//auth reset
router.get('/reset/:token', function(req, res) {
  User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
    if (!user) {
      req.flash('error', 'Password reset token is invalid or has expired.');
      return res.redirect('/auth/forgot');
    }
    res.render('reset', {
      user: req.user
    });
  });
});

router.post('/reset/:token', function(req, res) {
  async.waterfall([
    function(done) {
      User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
        if (!user) {
          req.flash('error', 'Password reset token is invalid or has expired.');
          return res.redirect('back');
        }
        user.password = req.body.password;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;

        user.save(function(err) {
          req.login(user, function(err) {
            done(err, user);
          });
        });
      });
    },
    function(user, done) {
			var transporter = nodemailer.createTransport({
			  service: 'gmail',
			  auth: {
					user: keys.mail.email,
					pass: keys.mail.password
			  }
			});
      var mailOptions = {
        to: user.email,
        from: '4Times',
        subject: 'Your password has been changed',
        text: 'Hello,\n\n' +
          'This is a confirmation that the password for your account ' + user.email + ' has just been changed.\n'
      };
      transporter.sendMail(mailOptions, function(err,info) {
				if (err) {
					req.flash('error_msg', 'Unable to send email '+err);
				} else {
					console.log('Email sent: \n' + info.response);
        	req.flash('success_msg', 'Success! Your password has been changed.');
				}
				done(err);
      });
    }
  ], function(err) {
    res.redirect('/profile');
  });
});

// var google_scopes= [
// 		'https://www.googleapis.com/auth/plus.login' ,
// 		'https://www.googleapis.com/auth/calendar' ,
// 		'https://www.googleapis.com/auth/calendar.readonly' ,
// 		'https://www.googleapis.com/auth/contacts' ,
// 		'https://www.googleapis.com/auth/contacts.readonly' ,
// 		'https://www.googleapis.com/auth/userinfo.profile' ,
// 		'https://www.googleapis.com/auth/userinfo.email' ,
// 		'https://www.googleapis.com/auth/user.addresses.read' ,
// 		'https://www.googleapis.com/auth/user.birthday.read' ,
// 		'https://www.googleapis.com/auth/user.emails.read' ,
// 		'https://www.googleapis.com/auth/user.phonenumbers.read'
//  ];

//auth with google
router.get('/google',
  passport.authenticate('google',{scope:['profile','email']}));

// Facebook_scope visit https://developers.facebook.com/docs/facebook-login/permissions
//auth with facebook
router.get('/facebook',
  passport.authenticate('facebook',{scope:['user_birthday','email']}));


//callback route for google to redirect to
router.get('/google/redirect',passport.authenticate('google'),(req,res)=>{
	req.flash('success_msg','You have successfully Logged in');
  res.redirect('/profile');
});

//callback route for facebook to redirect to
router.get('/facebook/redirect',
  passport.authenticate('facebook', { failureRedirect: '/login' }),(req, res)=>{
		req.flash('success_msg','You have successfully Logged in');
    res.redirect('/profile');
  });

module.exports=router;
