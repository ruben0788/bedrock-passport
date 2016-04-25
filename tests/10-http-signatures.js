/*
 * Copyright (c) 2016 Digital Bazaar, Inc. All rights reserved.
 */
 /* globals describe, before, after, it, should, beforeEach, afterEach */
 /* jshint node: true */
'use strict';

var _ = require('lodash');
var async = require('async');
var bedrock = require('bedrock');
var brKey = require('bedrock-key');
var brKeyHttp = require('bedrock-key-http');
var config = bedrock.config;
var helpers = require('./helpers');
var brIdentity = require('bedrock-identity');
var database = require('bedrock-mongodb');
var mockData = require('./mock.data');
var store = require('bedrock-credentials-mongodb').provider;
var uuid = require('node-uuid').v4;
var url = require('url');
var util = bedrock.util;
var request = require('request');
request = request.defaults({json: true, strictSSL: false});

var urlObj = {
  protocol: 'https',
  host: config.server.host,
  pathname: ''
};

describe('bedrock-passport http-signature queries', function() {
  before('Prepare the database', function(done) {
    helpers.prepareDatabase(mockData, done);
  });
  after('Remove test data', function(done) {
    helpers.removeCollections(done);
  });
  beforeEach('Erase credentials', function(done) {
    helpers.removeCollection('credentialProvider', done);
  });
  describe('authenticated requests with no URL parameters', function() {
    it.only('completes successfully', function(done) {
      async.auto({
        query: function(callback) {
          var clonedUrlObj = util.clone(urlObj);
          request.get(
            helpers.createHttpSignatureRequest(
              url.format(clonedUrlObj), user),
            function(err, res, body) {
              should.not.exist(err);
              should.exist(body);
              callback();
            });
        }
      }, done);
    });
  });
});
