const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const Schema = mongoose.Schema;

const userSchema = new Schema({
	name: String,
	email: {
		type: String,
		required: true,
		index: { unique: true },
		trim: true
	},
	emailPresent: { type: Boolean, default: false },
	verifyEmailToken: String,
	verifyEmailExpires: Date,
	verifiedEmail: { type: Boolean, default: false },

	gender: String,
	thumbnail: String,
	DOB: Date,
	mobile: String,

	password: { type: String }, //password required control at post request
	resetPasswordToken: String,
	resetPasswordExpires: Date,

	facebookId: String,
	googleId: String,
	linkedinId: String,
});

userSchema.statics.HashPassword = async function (candidatePassword) {
	var SALT_FACTOR = 10;
	var hashValue = await bcrypt.
		genSalt(SALT_FACTOR).
		then((salt) => {
			return bcrypt.hash(candidatePassword, salt)
		}).then((hash) => {
			return hash;
		})
	return hashValue;
};

var User = module.exports = mongoose.model('User', userSchema);

module.exports.comparePassword = function (candidatePassword, hash, callback) {
	bcrypt.compare(candidatePassword, hash, function (err, isMatch) {
		callback(null, isMatch);
	});
}

module.exports.getUserById = function (id, callback) {
	User.findById(id, callback);
}
