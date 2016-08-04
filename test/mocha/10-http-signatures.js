/*
 * Copyright (c) 2016 Digital Bazaar, Inc. All rights reserved.
 */
/* globals describe, before, after, it, should, beforeEach, afterEach */
/* jshint node: true */
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
      var user = mockData.identities.mock;
      it('dereference lookup completes successfully', function(done) {
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
    });
  });
});
