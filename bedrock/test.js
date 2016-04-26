/*
 * Copyright (c) 2016 Digital Bazaar, Inc. All rights reserved.
 */
var bedrock = require('bedrock');
var rest = require('bedrock-rest');

var brPassport = require('../lib/passport.js');

bedrock.events.on('bedrock-express.configure.routes', addMockRoutes);

bedrock.start();

function addMockRoutes(app) {
  var mockData = require('../tests/mock.data');
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
}
