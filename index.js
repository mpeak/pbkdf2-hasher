
// Exposes functions to generate and verify password hashes. Uses PBKDF2 with HMAC-SHA1
// which is built-in as part of Node's crypto module, and, as such, should be fast(-ish).

var _btoa = require('btoa');
var crypto = require('crypto');

function generateSalt(bytes, callback) {
	crypto.randomBytes(bytes, function(ex, buf) {
		if (ex) return callback(ex);
		callback(null, _btoa(buf));
	});
}

function generateHash(password, salt, iterations, keylen, callback) {
	crypto.pbkdf2(password, salt, iterations, keylen, function(err, key) {
		if (err) return callback(err);
		var hash = _btoa(key);
		hash = [ 'pbkdf2sha1', iterations, salt, hash ].join('$');
		callback(null, hash);
	});
}

// Hashes a password with 10,000 iterations of PBKDF2 SHA1 using a salt of 20 random bytes
// represented as a base36 string. The callback gets two arguments (err, hash). The hash
// argument is set in this format:
//
//     algorithm$iterations$salt$passwordhash
//
// Which looks like this in practice:
//
//     pbkdf2sha1$10000$salt$passwordhash
function generate(password, callback) {
	generateSalt(20, function(ex, salt) {
		if (ex) return callback(ex);
		generateHash(password, salt, 10000, 20, function(err, hash) {
			if (err) return callback(err);
			callback(null, hash);
		});
	});
}

// Verifies a password against a hash. It ignores the algorithm part because we only support
// pbkdf2sha1, but it respects the number of iterations and salt stored in the hash when
// recalculating it. The callback gets two arguments (err, isVerified).
function verify(password, hashedPassword, callback) {
	var parts = hashedPassword.split('$');
	generateHash(password, parts[2], parseInt(parts[1], 10), 20, function(err, key) {
		if (err) return callback(err);
		callback(null, hashedPassword == key);
	});
}

exports.generate = generate;
exports.verify = verify;
