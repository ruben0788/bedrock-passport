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
    rest.when.prefers.jsonld,
    rest.linkedDataHandler({
      get: function(req, res, callback) {
        brPassport.authenticate('signature', {}, function(err, user) {
          callback(err, user);
        })(req, res, function(err) {
          callback(err);
        });
      }
    })
  );
  app.get('/tests/keys/1',
    rest.when.prefers.jsonld,
    rest.linkedDataHandler({
      get: function(req, res, callback) {
        var key = mockData.key;
        callback(null, key);
      }
    })
  );
  app.get('/tests/i/mock',
    rest.when.prefers.jsonld,
    rest.linkedDataHandler({
      get: function(req, res, callback) {
        var owner1 = mockData.owner1;
        callback(null, owner1);
      }
    })
  );
});
