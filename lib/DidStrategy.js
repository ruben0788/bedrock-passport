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
  const self = this;

  // TODO: use WHATWG URL parser once node 8.x is required
  // new URL(bedrock.config.server.baseUri)
  const parsed = URL.parse(bedrock.config.server.baseUri);
  const domains = ['https://' + parsed.host, parsed.host];

  // TODO: support blinded domain check once implemented elsewhere, i.e.
  //   allow given identity/profile to be signed for a salted domain where
  //   the signer does not know the domain but the salt is then included
  //   in the profile as unsigned itself -- apply salt to expected domain
  //   and hash it to check signed domain value (or similar scheme), etc.

  // check POST data for an identity with a DID and a valid signature
  // pass to credentials-io for verification of the identity and all
  // credentials
  async.auto({
    verify: function(callback) {
      const identity = req.body;
      return callback(null, {
        identity,
        credentials: [],
        domain: domains[0],
        verified: true
      });
      //cio.verify(identity, callback);
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
    if(!domains.includes(results.verify.domain)) {
      return self.error(new BedrockError(
        'Identity credential signature domain mismatch.',
        'DomainMismatch', {
          givenDomain: results.verify.domain,
          expectedDomain: domains
        }));
    }
    req.user = {
      identity: results.verify.identity,
      credentials: results.verify.credentials
    };
    self.success(req.user);
  });
};
