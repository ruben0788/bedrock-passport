/*
 * Copyright (c) 2016 Digital Bazaar, Inc. All rights reserved.
 */
/* jshint node: true */
'use strict';

var bedrock = require('bedrock');
var brPassport = require('../lib/passport');
var config = bedrock.config;
var mockData = require('../test/mocha/mock.data');
var path = require('path');
var rest = require('bedrock-rest');

config.mocha.tests.push(path.join(__dirname, '..', 'test', 'mocha'));

// MongoDB
config.mongodb.name = 'bedrock_passport_test';
config.mongodb.host = 'localhost';
config.mongodb.port = 27017;
config.mongodb.local.collection = 'bedrock_passport_test';
config.mongodb.username = 'bedrock';
config.mongodb.password = 'password';
config.mongodb.adminPrompt = true;
config.mongodb.dropCollections.onInit = true;
config.mongodb.dropCollections.collections = [];

bedrock.events.on('bedrock-express.configure.routes', function(app) {
  app.get('/tests/bedrock-passport/http-signature-test',
    brPassport.ensureAuthenticated,
    rest.when.prefers.jsonld,
    rest.linkedDataHandler({
      get: function(req, res, callback) {
        callback(null, req.user);
      }
    })
  );
  Object.keys(mockData.keys).forEach(function(k) {
    app.get('/keys/' + k,
      rest.when.prefers.jsonld,
      rest.linkedDataHandler({
        get: function(req, res, callback) {
          callback(null, mockData.keys[k]);
        }
      })
    );
  });
  Object.keys(mockData.owners).forEach(function(o) {
    app.get('/tests/i/' + o,
      rest.when.prefers.jsonld,
      rest.linkedDataHandler({
        get: function(req, res, callback) {
          callback(null, mockData.owners[o]);
        }
      })
    );
  });
});
