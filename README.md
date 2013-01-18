pbkdf2-hasher
=============

Password hashing and verification for Node using the built-in crypto.pbkdf2 (HMAC-SHA1).

The number of iterations is fixed to 10,000. The salt is a randomly-generated 160-bit value.
Both the salt and password hash are represented in base64 so the combined hash can be stored
as a string and easily saved (e.g. to a database).

# Installation

    $ npm install pbkdf2-hasher

# Usage

Both generating and verifying the hash take an async callback, because PBKDF2 is meant
to take a significant time to process.

## Generating a hash

    var hasher = require('pbkdf2-hasher');
    hasher.generate('mypassword', function(err, hash) {
        // `hash` has the format "algorithm$iterations$salt$hash".
    });

## Verifying a hash

	var hasher = require('pbkdf2-hasher');
    hasher.verify('mypassword', 'myhash', function(err, verified) {
        // `verified` is true or false.
    });
