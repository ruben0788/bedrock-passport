/*
 * Copyright (c) 2013-2016 Digital Bazaar, Inc. All rights reserved.
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
var didio = require('did-io');
var jsonld = require('jsonld');
var URL = require('url');
var request = require('request');
request = request.defaults({
  headers: {'Accept': 'application/ld+json; application/json'},
  json: true,
  strictSSL: false
});

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
      callback();
    }],
    getPublicKey: ['checkRequest', function(callback, results) {
      var publicKey = {id: results.parseRequest.keyId};
      brKey.getPublicKey(publicKey, function(err, key) {
        if(err && err.name === 'NotFound') {
          // Retrieve the public key based on the ID's
          // URL scheme when we can't find it in our database.
          return getPublicKey(publicKey.id, function(err, key) {
            callback(err, key);
          });
        }
        return callback(err, key);
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
      callback();
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
    validateHost: ['verify', function(callback) {
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
      callback();
    }],
    validateNonce: ['validateHost', function(callback, results) {
      // FIXME: !!!!!!! Implement nonce tracking here !!!!!!!!!!!
      callback();
    }],
    // TODO: eventually remove and set identity elsewhere only when needed
    //       via bedrock.events.on('bedrock-passport.authenticate', ...)
    getIdentity: ['validateNonce', function(callback, results) {
      // get identity without permission check
      brIdentity.get(null, results.getPublicKey.owner, function(err, identity) {
        if(err) {
          if(err.name === 'NotFound') {
            // fallback to basic id
            return callback(null, {
              '@context': bedrock.config.constants.IDENTITY_CONTEXT_V1_URL,
              id: results.getPublicKey.owner
            });
          }
          return callback(err);
        }
        callback(null, identity);
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

// decides which scheme to use to look up the public key
function getPublicKey(publicKey, callback) {
  // get scheme from public key ID (URL)
  var scheme = URL.parse(publicKey).protocol || ':';
  scheme = scheme.substr(0, scheme.length - 1);

  // dereference URL if supported
  var dereferenceUrlScheme =
    bedrock.config.passport.strategies.signature.dereferenceUrlScheme;
  if(dereferenceUrlScheme[scheme]) {
    if(scheme === 'did') {
      return getDidPublicKey(publicKey, callback);
    }
    if(scheme === 'https') {
      return getHttpsPublicKey(publicKey, callback);
    }
  }

  return callback(new BedrockError(
    'URL scheme "' + scheme + '" is not supported.',
    'HttpSignature.UnsupportedUrlScheme', {
      'public': true,
      httpStatusCode: 400,
      scheme: scheme
    }));
}

function getDidPublicKey(publicKey, callback) {
  didio.get(publicKey, {
    baseUrl: bedrock.config.passport.strategies.did.didio.baseUrl
  }, callback);
}

// 1. resolve key ID => should contain public key info including key material
// (and owner)
// 2. resolve owner ID and get identity info and list of public keys
// 3. make sure key ID is listed in list of keys -- if so, verified
function getHttpsPublicKey(publicKey, callback) {
  async.auto({
    dereferencePublicKey: function(callback) {
      request.get(publicKey, function(err, res) {
        callback(err, res.body);
      });
    },
    dereferenceOwner: ['dereferencePublicKey', function(callback, results) {
      var dereferencedKey = results.dereferencePublicKey;
      var owner = dereferencedKey.owner;
      if(!owner) {
        return callback(new BedrockError(
          'PublicKey owner document not found',
          'HttpSignature.VerifyFailure', {
            'public': true,
            httpStatusCode: 400
          }));
      }
      // Owner's document must be an https:// url
      var scheme = URL.parse(owner).protocol || ':';
      scheme = scheme.substr(0, scheme.length - 1);
      if(scheme !== 'https') {
        return callback(new BedrockError(
          'URL scheme "' + scheme + '" is not supported for owner IDs.',
          'HttpSignature.UnsupportedUrlScheme', {
            'public': true,
            httpStatusCode: 400,
            scheme: scheme
          }));
      }

      request.get(owner, function(err, res) {
        callback(err, res.body);
      });
    }],
    verify: ['dereferenceOwner', function(callback, results) {
      var dereferencedOwner = results.dereferenceOwner;
      var dereferencedKey = results.dereferencePublicKey;

      if(!dereferencedOwner) {
        return callback(new BedrockError(
          'PublicKey owner document not found',
          'HttpSignature.VerifyFailure', {
            'public': true,
            httpStatusCode: 400
          }));
      }

      var ownerKeys = jsonld.getValues(dereferencedOwner, 'publicKey');
      var found = false;
      for(var i = 0; i < ownerKeys.length; ++i) {
        var key = ownerKeys[i];
        if(key.id === dereferencedKey.id) {
          found = true;
          break;
        }
      }
      if(!found) {
        return callback(new BedrockError(
          'PublicKey not found in owner\'s document',
          'HttpSignature.VerifyFailure', {
            'public': true,
            httpStatusCode: 400
          }));
      }
      callback(null, dereferencedKey);
    }]
  }, function(err, results) {
    callback(err, results.verify);
  });
}
