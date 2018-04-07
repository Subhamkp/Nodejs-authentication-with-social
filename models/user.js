const mongoose = require('mongoose');
const bcrypt   = require('bcryptjs');
const Schema=mongoose.Schema;

const userSchema=new Schema({
	name: String,

	email: {
		type: String,
		required: true,
		index: { unique: true },
		trim: true
	},
	setEmail:{type:Boolean,default:false},
	verifyEmailToken: String,
	verifyEmailExpires: Date,
	verifiedEmail:{type:Boolean,default:false},

	gender:String,
	thumbnail:String,
	DOB: Date,
	mobile:String,

	password: { type: String}, //password required control at post request
	resetPasswordToken: String,
  resetPasswordExpires: Date,

	facebookId: String,
	googleId:String,
	linkedinId:String,
});

var User=module.exports=mongoose.model('User',userSchema);
// model is exported to create a new instance and it is also saved here for other functions to run on User as whole
userSchema.pre('save', function(next) {
  var user = this;
  var SALT_FACTOR = 10;

  if (!user.isModified('password')) return next();
  bcrypt.genSalt(SALT_FACTOR, function(err, salt) {
    if (err) return next(err);

    bcrypt.hash(user.password, salt,function(err, hash) {
      if (err) return next(err);
      user.password = hash;
      next();
    });
  });
});


module.exports.comparePassword = function(candidatePassword, hash, callback){
	bcrypt.compare(candidatePassword, hash, function(err, isMatch) {
    	callback(null, isMatch);
	});
}

module.exports.getUserById = function(id, callback){
	User.findById(id, callback);
}
