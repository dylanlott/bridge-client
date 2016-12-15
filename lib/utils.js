/**
 * @module bridge-client/utils
 * @license LGPL-3.0
 */

'use strict';

var request = require('request');
var assert = require('assert');
var crypto = require('crypto');
var Buffer = require('buffer/').Buffer;
var constants = require('./constants');

/**
 * Returns the SHA-1 hash of the input
 * @param {String|Buffer} input - Data to hash
 * @param {String} encoding - The encoding type of the data
 * @returns {String}
 */
module.exports.sha1 = function(input, encoding) {
  return crypto.createHash('sha1').update(input, encoding).digest('hex');
};

/**
 * Returns the SHA-256 hash of the input
 * @param {String|Buffer} input - Data to hash
 * @param {String} encoding - The encoding type of the data
 * @returns {String}
 */
module.exports.sha256 = function(input, encoding) {
  return crypto.createHash('sha256').update(input, encoding).digest('hex');
};

/**
 * Returns the SHA-512 hash of the input
 * @param {String|Buffer} input - Data to hash
 * @param {String} encoding - The encoding type of the data
 * @returns {String}
 */
module.exports.sha512 = function(input, encoding) {
  return crypto.createHash('sha512').update(input, encoding).digest('hex');
};


/**
 * Returns the RIPEMD-160 hash of the input
 * @param {String|Buffer} input - Data to hash
 * @param {String} encoding - The encoding type of the data
 * @returns {String}
 */
module.exports.rmd160 = function(input, encoding) {
  return crypto.createHash('rmd160').update(input, encoding).digest('hex');
};


/**
 * Returns the WHIRLPOOL hash of the input
 * @param {String|Buffer} input - Data to hash
 * @param {String} encoding - The encoding type of the data
 * @returns {String}
 */
module.exports.whirlpool = function(input, encoding) {
  return crypto.createHash('whirlpool').update(input, encoding).digest('hex');
};


/**
 * Returns the RIPEMD-160 SHA-256 hash of this input
 * @param {String|Buffer} input - Data to hash
 * @param {String} encoding - The encoding type of the data
 * @returns {String}
 */
module.exports.rmd160sha256 = function(input, encoding) {
  return module.exports.rmd160(
    Buffer(module.exports.sha256(input, encoding), 'hex')
  );
};



/**
 * Returns the SHA-1 WHIRLPOOL hash of this input
 * @param {String|Buffer} input - Data to hash
 * @param {String} encoding - The encoding type of the data
 * @returns {String}
 */
module.exports.sha1whirlpool = function(input, encoding) {
  return module.exports.sha1(
    Buffer(module.exports.whirlpool(input, encoding), 'hex')
  );
};


/**
 * Returns the next power of two number
 * @param {Number} number
 * @returns {Number}
 */
module.exports.getNextPowerOfTwo = function(num) {
  return Math.pow(2, Math.ceil(Math.log(num) / Math.log(2)));
};

/**
 * Generates a unique token
 * @returns {String}
 */
module.exports.generateToken = function() {
  return module.exports.rmd160sha256(crypto.randomBytes(512));
};


/**
 * Returns a stringified URL from the supplied contact object
 * @param {Object} contact
 * @param {String} contact.address
 * @param {Number} contact.port
 * @param {String} contact.nodeID
 * @returns {String}
 */
module.exports.getContactURL = function(contact) {
  return [
    'storj://', contact.address, ':', contact.port, '/', contact.nodeID
  ].join('');
};


/**
 * Determines if a value is hexadecimal string
 * @param {*} a - The value to be tested
 * @returns {Boolean}
 */
module.exports.isHexaString = function(a) {
  if (typeof a !== 'string') {
    return false;
  }
  return /^[0-9a-fA-F]+$/.test(a);
};
