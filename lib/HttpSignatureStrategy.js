/*
 * Copyright (c) 2013-2015 Digital Bazaar, Inc. All rights reserved.
 */
var _ = require('lodash');
var async = require('async');
var bedrock = require('bedrock');
var brIdentity = require('bedrock-identity');
var brKey = require('bedrock-key');
var httpSignature = require('http-signature');
var passport = require('passport');
var util = require('util');
var BedrockError = bedrock.util.BedrockError;

module.exports = Strategy;

var REQUIRED_HEADERS = ['request-line', 'host', 'date'];

/**
 * Creates a new HttpSignatureStrategy for use with passport.
 */
function Strategy() {
  passport.Strategy.call(this);
  this.name = 'signature';
}
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate a request.
 *
 * @param req the request to authenticate.
 */
Strategy.prototype.authenticate = function(req) {
  var self = this;

  // check that message is signed with the Signature scheme
  // check for 'Authorization: Signature ...'
  var found = false;
  var auth = req.get('Authorization');
  if(auth) {
    var parts = auth.split(' ');
    if(parts && parts.length > 0 && parts[0] === 'Signature') {
      found = true;
    }
  }
  if(!found) {
    // TODO: seems like an invalid use of the passport API, fail is
    // expecting an optional challenge string not an error?
    return self.fail(new BedrockError(
      'Request is not signed.',
      'HttpSignature.NotSigned'));
  }

  async.auto({
    parseRequest: function(callback) {
      var parsed;
      try {
        parsed = httpSignature.parseRequest(req);
      } catch(ex) {
        return callback(new BedrockError(
          'Request signature parse error.',
          'HttpSignature.ParseError',
          null, ex));
      }
      callback(null, parsed);
    },
    checkRequest: ['parseRequest', function(callback, results) {
      var diff = _.difference(
        REQUIRED_HEADERS,
        results.parseRequest.params.headers);
      if(diff.length > 0) {
        return callback(new BedrockError(
          'Missing required headers in HTTP signature.',
          'HttpSignature.MissingHeaders', {
            'public': true,
            httpStatusCode: 400,
            requiredHeaders: REQUIRED_HEADERS
          }));
      }
      callback(null);
    }],
    getPublicKey: ['checkRequest', function(callback, results) {
      var publicKey = {id: results.parseRequest.keyId};
      brKey.getPublicKey(
        publicKey, function(err, publicKey) {
          callback(err, publicKey);
        });
    }],
    validatePublicKey: ['getPublicKey', function(callback, results) {
      if(results.getPublicKey.revoked &&
        _timestampBeforeNow(results.getPublicKey.revoked)) {
          return callback(new BedrockError(
            'Public key has been revoked.',
            'HttpSignature.PublicKeyRevocation', {
              'public': true,
              httpStatusCode: 400,
              publicKey: {
                id: results.getPublicKey.id,
                revoked: results.getPublicKey.revoked
              }
            }));
        }
      callback(null);
    }],
    verify: ['validatePublicKey', function(callback, results) {
      var verified;
      try {
        verified = httpSignature.verifySignature(
          results.parseRequest, results.getPublicKey.publicKeyPem);
      } catch(ex) {
        return callback(new BedrockError(
          'Request signature verify error.',
          'HttpSignature.VerifyError', {cause: ex}));
      }
      if(!verified) {
        return callback(new BedrockError(
          'Request signature verification failed.',
          'HttpSignature.VerifyFailure'));
      }
      callback();
    }],
    validateHost: ['verify', function(callback, results) {
      if(req.headers.host !== bedrock.config.server.host) {
        return callback(new BedrockError(
          'Host header contains an invalid host name.',
          'HttpSignature.InvalidHostHeader', {
            'public': true,
            httpStatusCode: 400,
            headers: {
              host: req.headers.host
            }
          }));
      }
      callback(null);
    }],
    validateNonce: ['validateHost', function(callback, results) {
      // FIXME: !!!!!!! Implement nonce tracking here !!!!!!!!!!!
      callback(null);
    }],
    getIdentity: ['validateNonce', function(callback, results) {
      // get identity without permission check
      brIdentity.get(
        null, results.getPublicKey.owner, function(err, identity) {
          callback(err, identity);
        });
    }]
  }, function(err, results) {
    if(err) {
      return self.error(err);
    }
    req.user = {
      identity: results.getIdentity
    };
    self.success(req.user);
  });
};

// returns true if the given timestamp is before the current time
function _timestampBeforeNow(timestamp) {
  var now = new Date();
  var tsDate = new Date(timestamp);
  return tsDate < now;
}
