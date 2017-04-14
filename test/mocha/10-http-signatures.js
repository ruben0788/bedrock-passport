/*
 * Copyright (c) 2016-2017 Digital Bazaar, Inc. All rights reserved.
 */
/* globals should */
'use strict';

var async = require('async');
var bedrock = require('bedrock');
var config = bedrock.config;
var helpers = require('./helpers');
var mockData = require('./mock.data');
var url = require('url');
var util = bedrock.util;
var request = require('request');
request = request.defaults({json: true, strictSSL: false});

var urlObj = {
  protocol: 'https',
  host: config.server.host,
  pathname: '/tests/bedrock-passport/http-signature-test'
};

describe('bedrock-passport', function() {
  describe('authenticated requests using http-signature', function() {
    describe('using dereference lookup', function() {
      it('dereference lookup completes successfully', function(done) {
        var user = mockData.identities.alpha;
        async.auto({
          authenticate: function(callback) {
            var clonedUrlObj = util.clone(urlObj);
            request.get(helpers.createHttpSignatureRequest(
              url.format(clonedUrlObj), user),
              function(err, res) {
                callback(err, res.body);
              });
          },
          checkResults: ['authenticate', function(callback, results) {
            // Should return a barebones identity
            var identity = results.authenticate.identity;
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
      it('dereference lookup fails', function(done) {
        var user = mockData.identities.beta;
        async.auto({
          authenticate: function(callback) {
            var clonedUrlObj = util.clone(urlObj);
            request.get(helpers.createHttpSignatureRequest(
              url.format(clonedUrlObj), user),
              function(err, res) {
                callback(err, res);
              });
          },
          checkResults: ['authenticate', function(callback, results) {
            // Should return a barebones identity
            var res = results.authenticate;
            res.statusCode.should.equal(400);
            should.exist(res.body);
            should.exist(res.body.type);
            res.body.type.should.equal('PermissionDenied');
            callback();
          }]
        }, done);
      });
      // gamma has no published public key document
      it('should fail if key document URL is unavailable', function(done) {
        var user = mockData.identities.gamma;
        async.auto({
          authenticate: function(callback) {
            var clonedUrlObj = util.clone(urlObj);
            request.get(helpers.createHttpSignatureRequest(
              url.format(clonedUrlObj), user),
              function(err, res) {
                callback(err, res);
              });
          },
          checkResults: ['authenticate', function(callback, results) {
            // Should return a barebones identity
            var res = results.authenticate;
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
      it('should fail if owner URL is unavailable', function(done) {
        var user = mockData.identities.delta;
        async.auto({
          authenticate: function(callback) {
            var clonedUrlObj = util.clone(urlObj);
            request.get(helpers.createHttpSignatureRequest(
              url.format(clonedUrlObj), user),
              function(err, res) {
                callback(err, res);
              });
          },
          checkResults: ['authenticate', function(callback, results) {
            // Should return a barebones identity
            var res = results.authenticate;
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
      it('fails if owner doc references wrong public key', function(done) {
        var user = mockData.identities.epsilon;
        async.auto({
          authenticate: function(callback) {
            var clonedUrlObj = util.clone(urlObj);
            request.get(helpers.createHttpSignatureRequest(
              url.format(clonedUrlObj), user),
              function(err, res) {
                callback(err, res);
              });
          },
          checkResults: ['authenticate', function(callback, results) {
            // Should return a barebones identity
            var res = results.authenticate;
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
