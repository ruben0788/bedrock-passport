/*
 * Copyright (c) 2015 Digital Bazaar, Inc. All rights reserved.
 */
var _ = require('underscore');
var async = require('async');
var bedrock = require('bedrock');
var brIdentity = require('bedrock-identity');
var cio = require('credentials-io');
var passport = require('passport');
var util = require('util');
var BedrockError = bedrock.util.BedrockError;

module.exports = Strategy;

/**
 * Creates a new DidStrategy for use with passport.
 */
function Strategy() {
  passport.Strategy.call(this);
  this.name = 'did';
}
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate a request.
 *
 * @param req the request to authenticate.
 */
Strategy.prototype.authenticate = function(req) {
  var self = this;

  // check POST data for an identity with a DID and a valid signature
  // pass to credentials-io for verification of the identity and all
  // credentials
  async.auto({
    parseIdentity: function(callback) {
      var parsed;
      try {
        parsed = JSON.parse(req.body.jsonPostData);
      } catch(ex) {
        return callback(new BedrockError(
          'Credentials request parse error.', 'ParseError',
          null, ex));
      }
      callback(null, parsed);
    },
    verify: ['parseIdentity', function(callback, results) {
      var identity = results.parseIdentity;
      cio.verify(identity, callback);
    }]
  }, function(err, results) {
    if(err) {
      return self.error(err);
    }
    if(!results.verify.verified) {
      return self.error(new BedrockError(
        'Identity credential signature verification failed.',
        'SignatureNotVerified'));
    }
    req.user = {
      identity: results.verify.identity,
      credentials: results.verify.credentials
    };
    self.success(req.user);
  });
};
