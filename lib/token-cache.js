var debug = require('debug')('google-oauth-jwt');

/**
 * A cache of tokens for reusing previously requested tokens until they expire.
 *
 * Tokens are requested by calling the `authenticate` method and cached for any combination of `options.email` and
 * `options.scopes`.
 *
 * @constructor TokenCache
 */
function TokenCache() {
	// cache is just a key/value pair
	this._cache = {};
};

/**
 * Retrieve an authentication token, or reuse a previously obtained one if it is not expired.
 * Only one request will be performed for any combination of `options.email`, `options.scopes`
 * and `options.delegationEmail`.
 *
 * @param options The JWT generation options.
 * @callback {Function} The callback to invoke with the resulting token.
 */
TokenCache.prototype.get = function (options, callback) {
	console.log('Starting into get function of TokenCache with options: ', options);
	var key = options.email + ':' + options.scopes.join(',');
	console.log('Key is: ', key);
	if (options.delegationEmail) key += ':' + options.delegationEmail;
	console.log('Checking cache: ', ths._cache);
	if (!this._cache[key]) {
		console.log('Key not found in cache. Going to request new token');
		this._cache[key] = new TokenRequest(this.authenticate, options);
	} else {
		console.log('Key found in the cache');
	}
	this._cache[key].get(callback);
};

/**
 * Clear all tokens previously requested by this instance.
 */
TokenCache.prototype.clear = function () {
	this._cache = {};
};

/**
 * The method to use to perform authentication and retrieving a token.
 * Used for overriding the authentication mechanism.
 *
 * @param {Object} options The JWT generation options.
 * @callback {Function} callback The callback to invoke with the resulting token.
 */
TokenCache.prototype.authenticate = require('./auth').authenticate;

/**
 * A single cacheable token request with support for concurrency.
 * @private
 * @constructor
 */
function TokenRequest(authenticate, options) {

	var self = this;
	this.status = 'expired';
	this.pendingCallbacks = [];

	// execute accumulated callbacks during the 'pending' state
	function fireCallbacks(err, token) {
		self.pendingCallbacks.forEach(function (callback) {
			callback(err, token);
		});
		self.pendingCallbacks = [];
	}

	TokenRequest.prototype.get = function (callback) {
		console.log('Inside TokenRequest.prototype.get and status is: ', this.status);
		if (this.status == 'expired') {

			this.status = 'pending';
			this.pendingCallbacks.push(callback);

			authenticate(options, function (err, token) {
				if (err) {
					self.status = 'expired';
					return fireCallbacks(err, null);
				}
				self.issued = Date.now();
				// self.duration = options.expiration || 60 * 60 * 1000;
				self.duration = 5 * 60 * 1000; // Get new token every 5 minutes
				self.token = token;
				self.status = 'completed';
				return fireCallbacks(null, token);
			});

		} else if (this.status == 'pending') {
			// wait for the pending request instead of issuing a new one
			this.pendingCallbacks.push(callback);
		} else if (this.status == 'completed') {

			if (this.issued + this.duration < Date.now()) {
				this.status = 'expired';
				debug('token is expired, a new token will be requested');
				this.get(callback);
			} else {
				callback(null, this.token);
			}

		}
	};
}

/**
 * The global token cache that can be used as a default instance.
 * @type TokenCache
 */
TokenCache.global = new TokenCache();

module.exports = TokenCache;
