/*!
 * Copyright (c) 2016-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const async = require('async');
const bedrock = require('bedrock');
const config = bedrock.config;
const helpers = require('./helpers');
const mockData = require('./mock.data');
const url = require('url');
const util = bedrock.util;
let request = require('request');
request = request.defaults({json: true, strictSSL: false});

const urlObj = {
  protocol: 'https',
  host: config.server.host,
  pathname: '/tests/bedrock-passport/http-signature-test'
};

describe('bedrock-passport', () => {
  describe('authenticated requests using http-signature', () => {
    describe('using dereference lookup', () => {
      it('dereference lookup completes successfully', done => {
        const user = mockData.identities.alpha;
        async.auto({
          authenticate: callback => {
            const clonedUrlObj = util.clone(urlObj);
            request.get(helpers.createHttpSignatureRequest(
              url.format(clonedUrlObj), user),
            (err, res) => callback(err, res.body));
          },
          checkResults: ['authenticate', (callback, results) => {
            // Should return a barebones identity
            const identity = results.authenticate.identity;
            should.exist(identity);
            should.exist(identity['@context']);
            identity.id.should.equal(user.identity.id);
            should.not.exist(identity.email);
            callback();
          }]
        }, done);
      });
      // beta signs the request with a private key that does not match the
      // published public key
      it('dereference lookup fails', done => {
        const user = mockData.identities.beta;
        async.auto({
          authenticate: callback => {
            const clonedUrlObj = util.clone(urlObj);
            request.get(helpers.createHttpSignatureRequest(
              url.format(clonedUrlObj), user),
            (err, res) => callback(err, res));
          },
          checkResults: ['authenticate', (callback, results) => {
            // Should return a barebones identity
            const res = results.authenticate;
            res.statusCode.should.equal(400);
            should.exist(res.body);
            should.exist(res.body.type);
            res.body.type.should.equal('PermissionDenied');
            callback();
          }]
        }, done);
      });
      // gamma has no published public key document
      it('should fail if key document URL is unavailable', done => {
        const user = mockData.identities.gamma;
        async.auto({
          authenticate: callback => {
            const clonedUrlObj = util.clone(urlObj);
            request.get(helpers.createHttpSignatureRequest(
              url.format(clonedUrlObj), user),
            (err, res) => callback(err, res));
          },
          checkResults: ['authenticate', (callback, results) => {
            // Should return a barebones identity
            const res = results.authenticate;
            res.statusCode.should.equal(400);
            should.exist(res.body);
            should.exist(res.body.type);
            res.body.type.should.equal('PermissionDenied');
            should.exist(res.body.cause);
            should.exist(res.body.cause.type);
            res.body.cause.type.should.equal('HttpSignature.VerifyFailure');
            should.exist(res.body.cause.message);
            res.body.cause.message.should.equal('Public key URL unavailable.');
            callback();
          }]
        }, done);
      });
      // delta has no published owner document
      it('should fail if owner URL is unavailable', done => {
        const user = mockData.identities.delta;
        async.auto({
          authenticate: callback => {
            const clonedUrlObj = util.clone(urlObj);
            request.get(helpers.createHttpSignatureRequest(
              url.format(clonedUrlObj), user),
            (err, res) => callback(err, res));
          },
          checkResults: ['authenticate', (callback, results) => {
            // Should return a barebones identity
            const res = results.authenticate;
            res.statusCode.should.equal(400);
            should.exist(res.body);
            should.exist(res.body.type);
            res.body.type.should.equal('PermissionDenied');
            should.exist(res.body.cause);
            should.exist(res.body.cause.type);
            res.body.cause.type.should.equal('HttpSignature.VerifyFailure');
            should.exist(res.body.cause.message);
            res.body.cause.message.should
              .equal('Public key verification failed.');
            callback();
          }]
        }, done);
      });
      // epsilon owner doc references alpha owner public key doc
      it('fails if owner doc references wrong public key', done => {
        const user = mockData.identities.epsilon;
        async.auto({
          authenticate: callback => {
            const clonedUrlObj = util.clone(urlObj);
            request.get(helpers.createHttpSignatureRequest(
              url.format(clonedUrlObj), user),
            (err, res) => callback(err, res));
          },
          checkResults: ['authenticate', (callback, results) => {
            // Should return a barebones identity
            const res = results.authenticate;
            res.statusCode.should.equal(400);
            should.exist(res.body);
            should.exist(res.body.type);
            res.body.type.should.equal('PermissionDenied');
            should.exist(res.body.cause);
            should.exist(res.body.cause.type);
            res.body.cause.type.should.equal('HttpSignature.VerifyFailure');
            should.exist(res.body.cause.message);
            res.body.cause.message.should
              .equal('Public key verification failed.');
            res.body.cause.details.error.should
              .equal('Error: [jsigs.verify] The public key is not owned by ' +
                'its declared owner.');
            callback();
          }]
        }, done);
      });
      // TODO:
      it('Fails if public key document is invalid.');
    });
  });
});
