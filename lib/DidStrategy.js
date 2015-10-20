/*
 * Copyright (c) 2015 Digital Bazaar, Inc. All rights reserved.
 */
var async = require('async');
var bedrock = require('bedrock');
var cio = require('credentials-io');
var passport = require('passport');
var util = require('util');
var BedrockError = bedrock.util.BedrockError;
var URL = require('url');

// TODO: set injectables
// jsigs.use('jsonld', bedrock.jsonld);
// cio.use('jsonld', bedrock.jsonld);
// cio.use('jsonld-signatures', jsigs);

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

  // TODO: should `.host` be used to include port as well? should
  // scheme be assumed to be `https`?
  var domain = URL.parse(bedrock.config.server.baseUri).hostname;

  // check POST data for an identity with a DID and a valid signature
  // pass to credentials-io for verification of the identity and all
  // credentials
  async.auto({
    verify: function(callback) {
      var identity = req.body;
      // FIXME: use cio.verify when it becomes possible to verify signatures
      // FIXME: remove this faked success
      var fakeVerify = {
        verified: true,
        identity: identity,
        credentials: identity.credential
      };
      callback(null, fakeVerify);
      //cio.verify(req.body, callback);
    }
  }, function(err, results) {
    if(err) {
      return self.error(err);
    }
    if(!results.verify.verified) {
      return self.error(new BedrockError(
        'Identity credential signature verification failed.',
        'SignatureNotVerified'));
    }
    if(results.domain !== domain) {
      return self.error(new BedrockError(
        'Identity credential signature domain mismatch.',
        'DomainMismatch'));
    }
    // TODO: check public key credential verification, do not pass if it
    // does not verify, but other credentials can pass w/o checks -- they
    // are application-specific

    req.user = {
      identity: results.verify.identity,
      credentials: results.verify.credentials
    };
    self.success(req.user);
  });
};
