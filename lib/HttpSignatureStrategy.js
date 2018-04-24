/*!
 * Copyright (c) 2013-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const _ = require('lodash');
const async = require('async');
const bedrock = require('bedrock');
const brIdentity = require('bedrock-identity');
const brKey = require('bedrock-key');
const httpSignature = require('http-signature');
let jsigs = require('jsonld-signatures');
const passport = require('passport');
const util = require('util');
const BedrockError = bedrock.util.BedrockError;
let didio = require('did-io');
let jsonld = require('jsonld');
const URL = require('url');
const request = require('request');

module.exports = Strategy;

const REQUIRED_HEADERS_OLD = ['request-line', 'host', 'date'];
const REQUIRED_HEADERS = ['(request-target)', 'host', 'date'];

bedrock.events.on('bedrock.init', () => {
  // get configured lib instances
  jsonld = jsonld();
  didio = didio();
  didio.use('jsonld', jsonld);
  jsonld.documentLoader = didio.createDocumentLoader({
    baseUrl: bedrock.config.passport.strategies.did.didio.baseUrl,
    wrap: (url, callback) => bedrock.jsonld.documentLoader(url, callback),
  });
  jsigs = jsigs();
  jsigs.use('jsonld', jsonld);
});

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
  const self = this;

  // check that message is signed with the Signature scheme
  // check for 'Authorization: Signature ...'
  let found = false;
  const auth = req.get('Authorization');
  if(auth) {
    const parts = auth.split(' ');
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
    parseRequest: callback => {
      let parsed;
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
    checkRequest: ['parseRequest', (results, callback) => {
      let diff = _.difference(
        REQUIRED_HEADERS,
        results.parseRequest.params.headers);
      if(diff.length > 0) {
        // old headers also valid
        diff = _.difference(
          REQUIRED_HEADERS_OLD,
          results.parseRequest.params.headers);
      }
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
    getPublicKey: ['checkRequest', (results, callback) => {
      const publicKey = {id: results.parseRequest.keyId};
      brKey.getPublicKey(publicKey, (err, key) => {
        if(err && err.name === 'NotFound') {
          // Retrieve the public key based on the ID's
          // URL scheme when we can't find it in our database.
          return getPublicKey(publicKey.id, (err, key) => callback(err, key));
        }
        return callback(err, key);
      });
    }],
    validatePublicKey: ['getPublicKey', (results, callback) => {
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
    verify: ['validatePublicKey', (results, callback) => {
      let verified;
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
    validateHost: ['verify', (results, callback) => {
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
    validateNonce: ['validateHost', (results, callback) => {
      // FIXME: !!!!!!! Implement nonce tracking here !!!!!!!!!!!
      callback();
    }],
    // TODO: eventually remove and set identity elsewhere only when needed
    //       via bedrock.events.on('bedrock-passport.authenticate', ...)
    getIdentity: ['validateNonce', (results, callback) => {
      // get identity without permission check
      brIdentity.get(null, results.getPublicKey.owner, (err, identity) => {
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
  }, (err, results) => {
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
  const now = new Date();
  const tsDate = new Date(timestamp);
  return tsDate < now;
}

// decides which scheme to use to look up the public key
function getPublicKey(publicKey, callback) {
  // get scheme from public key ID (URL)
  let scheme = URL.parse(publicKey).protocol || ':';
  scheme = scheme.substr(0, scheme.length - 1);

  // dereference URL if supported
  const dereferenceUrlScheme =
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
  const jsonRequest = request.defaults({
    headers: {'Accept': 'application/ld+json; application/json'},
    json: true,
    strictSSL: bedrock.config.passport.strategies.signature.strictSSLEnabled
  });

  async.auto({
    dereferencePublicKey: callback => {
      jsonRequest.get(publicKey, (err, res) => {
        if(err || res.statusCode !== 200) {
          const statusCode = res ? res.statusCode : 400;
          return callback(new BedrockError(
            'Public key URL unavailable.',
            'HttpSignature.VerifyFailure', {
              'public': true,
              httpStatusCode: statusCode,
              publicKey: {id: publicKey}
            }, err));
        }
        if(!(res.body && typeof res.body === 'object')) {
          return callback(new BedrockError(
            'Public key document is invalid.',
            'HttpSignature.VerifyFailure', {
              'public': true,
              httpStatusCode: 400,
              publicKey: {id: publicKey}
            }, err));
        }
        callback(null, res.body);
      });
    },
    verifyKey: ['dereferencePublicKey', (results, callback) => {
      jsigs.checkKey(results.dereferencePublicKey, err => {
        if(err) {
          return callback(new BedrockError(
            'Public key verification failed.',
            'HttpSignature.VerifyFailure', {
              'public': true,
              httpStatusCode: 400,
              publicKey: {id: publicKey},
              error: err.toString()
            }, err));
        }
        callback();
      });
    }]
  }, (err, results) => callback(err, results.dereferencePublicKey));
}
