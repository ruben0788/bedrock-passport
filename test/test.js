/*
 * Copyright (c) 2016 Digital Bazaar, Inc. All rights reserved.
 */
var bedrock = require('bedrock');
var brPassport = require('bedrock-passport');
var mockData = require('./mocha/mock.data');
var rest = require('bedrock-rest');

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

require('bedrock-test');
bedrock.start();
