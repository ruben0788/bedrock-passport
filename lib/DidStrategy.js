/*
 * Copyright (c) 2015-2016 Digital Bazaar, Inc. All rights reserved.
 */
var async = require('async');
var bedrock = require('bedrock');
var cio = require('credentials-io');
var didio = require('did-io');
var passport = require('passport');
var util = require('util');
var BedrockError = bedrock.util.BedrockError;
var URL = require('url');

module.exports = Strategy;

/**
 * Creates a new DidStrategy for use with passport.
 */
function Strategy() {
  passport.Strategy.call(this);
  this.name = 'did';

  // setup jsonld w/custom document loader
  cio = cio();
  var jsonld = bedrock.jsonld();
  didio.use('jsonld', jsonld);
  jsonld.documentLoader = didio.createDocumentLoader({
    wrap: function(url, callback) {
      return bedrock.jsonld.documentLoader(url, callback);
    },
    baseUrl: bedrock.config.passport.strategies.did.didio.baseUrl
  });
  cio.use('jsonld', jsonld, {configure: false});
}
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate a request.
 *
 * @param req the request to authenticate.
 */
Strategy.prototype.authenticate = function(req) {
  var self = this;

  // TODO: should scheme be assumed to be `https`?
  var domain = URL.parse(bedrock.config.server.baseUri).host;

  // check POST data for an identity with a DID and a valid signature
  // pass to credentials-io for verification of the identity and all
  // credentials
  async.auto({
    verify: function(callback) {
      var identity = req.body;
      cio.verify(identity, callback);
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
    if(results.verify.domain !== domain) {
      return self.error(new BedrockError(
        'Identity credential signature domain mismatch.',
        'DomainMismatch', {
          givenDomain: results.verify.domain,
          expectedDomain: domain
        }));
    }
    req.user = {
      identity: results.verify.identity,
      credentials: results.verify.credentials
    };
    self.success(req.user);
  });
};
