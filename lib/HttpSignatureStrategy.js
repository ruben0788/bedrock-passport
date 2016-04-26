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
request = request.defaults({json: true, strictSSL: false});

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
  console.log("&&&&&&&&&&&&&&&&&&&&&&");
  console.log("Called HttpSignatureStrategy Authenticate");
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
      console.log("Parse request finished");
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
      console.log("Check request finished");
      callback(null);
    }],
    getPublicKey: ['checkRequest', function(callback, results) {
      var publicKey = {id: results.parseRequest.keyId};
      console.log("keyID:\n", results.parseRequest.keyId);
      console.log("Calling brKey.getPublicKey");
      brKey.getPublicKey(publicKey, function(err, key) {
        console.log("brKey.getPublic key returned");
        if(err && err.name === 'NotFound' || true) {
          // Retrieve the public key based on the ID's
          // URL scheme.
          console.log("Calling getPublicKey after DB lookup");
          return getPublicKey(publicKey.id, function(err, key) {
            console.log("getPublicKey returned: ", key);
            callback(err, key);
          });
        }
        return callback(err, key);
      });
    }],
    validatePublicKey: ['getPublicKey', function(callback, results) {
      console.log("Public ID:\n", results.getPublicKey);
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
  console.log("Dereferenced ID scheme:", scheme);
  console.log("dereferenceUrlScheme ==", dereferenceUrlScheme);
  console.log("dereferenceUrlScheme[scheme] ==", dereferenceUrlScheme[scheme]);
  if(dereferenceUrlScheme[scheme] || true) {
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
  // TODO: implement
  console.log("Calling getHttpsPublicKey:", publicKey);
  async.auto({
    dereferencePublicKey: function(callback) {
      request.get(publicKey, function(err, res, body) {
        console.log("Dereferenced publicKey with result", res.body);
        if(err) {
          console.log("ERR", err);
        }
        callback(null, res.body);
      });
    },
    dereferenceOwner: ['dereferencePublicKey', function(callback, results) {
      var dereferencedKey = results.dereferencePublicKey;
      var owner = dereferencedKey.owner;
      request.get(owner, function(err, res, body) {
        console.log("Dereferenced owner with result", res.body);
        if(err) {
          console.log("ERR", err);
        }
        callback(null, res.body);
      });
    }],
    verify: ['dereferenceOwner', function(callback, results) {
      var dereferencedOwner = results.dereferenceOwner;
      var dereferencedKey = results.dereferencePublicKey;
      var ownerKeys = jsonld.getValues(dereferencedOwner, 'publicKey');
      var found = false;
      ownerKeys.forEach(function(key) {
        if(key.id === dereferencedKey.id) {
          found = true;
          return false;
        }
      });
      console.log("Found? ", found);
      if(!found) {
        return callback(new BedrockError(
          'PublicKey not found in owner\'s document',
          'HttpSignature.VerifyFailure', {
            'public': true,
            httpStatusCode: 400,
            scheme: scheme
          }));
      }
      callback(null, dereferencedKey);
    }]
  }, function(err, results) {
    callback(err, results.verify);
  });
}
