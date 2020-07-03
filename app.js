require('dotenv').config();
const express = require("express");
const expressValidator = require('express-validator');
const path = require('path');
const passport = require('passport');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const morgan = require('morgan');
const flash = require('connect-flash');
const mongoose = require('mongoose');
const { SESSION_COOKIE_KEY } = process.env;
const authRoutes = require('./routes/auth-routes');
const profileRoutes = require('./routes/profile-routes');
const passportSetup = require('./config/passport-setup');


const app = express();

// HTTPS server
var https = require('https');
var fs = require('fs');
var options = {
  key: fs.readFileSync('privateKey.key'),
  cert: fs.readFileSync('certificate.crt')
};

// set up view engine
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// set morgan to log info about our requests for development use.
app.use(morgan('dev'));

// BodyParser Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));


// Set Static Folder
app.use(express.static(path.join(__dirname, 'public')));

// initialize cookie-parser to allow us access the cookies stored in the browser.
app.use(cookieParser());

// initialize express-session to allow us track the logged-in user across sessions.
app.use(session({
  key: 'user_sid',
  secret: SESSION_COOKIE_KEY,
  resave: false,
  saveUninitialized: false,
  cookie: {
    expires: 24 * 60 * 60 * 60 * 1000,
    secure: true
  }
}));

// initialize passport
app.use(passport.initialize());
app.use(passport.session());

// Connect to mongo DB
const url = process.env.MONGODB_URI;
mongoose.connect(url, { useNewUrlParser: true, useUnifiedTopology: true }, function (err) {
  if (err)
    console.log(err);
  else
    console.log('mongodb connected');
});

// Express Validator
app.use(expressValidator({
  errorFormatter: function (param, msg, value) {
    var namespace = param.split('.')
      , root = namespace.shift()
      , formParam = root;

    while (namespace.length) {
      formParam += '[' + namespace.shift() + ']';
    }
    return {
      param: formParam,
      msg: msg,
      value: value
    };
  }
}));

// Connect Flash (use after session as flas-messages are stored in sessions)
app.use(flash());

// Global Vars
app.use(function (req, res, next) {
  res.locals.success_msg = req.flash('success_msg');
  res.locals.success = req.flash('success');
  res.locals.error_msg = req.flash('error_msg');
  res.locals.error = req.flash('error');
  res.locals.user = req.user || null;
  next();
});

//create routes
app.use('/auth', authRoutes);
app.use('/profile/', profileRoutes);

//home route
app.get('/', (req, res) => {
  res.render('home', { user: req.user });
});

// Set Port
app.set('port', process.env.PORT);

https.createServer(options, app).listen(app.get('port'), function () {
  console.log('Server started on port ' + app.get('port'));
});

// app.listen(app.get('port'), function () {
//   console.log('Server started on port ' + app.get('port'));
// });
