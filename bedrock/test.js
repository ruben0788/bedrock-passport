/*
 * Copyright (c) 2016 Digital Bazaar, Inc. All rights reserved.
 */
var bedrock = require('bedrock');
var rest = require('bedrock-rest');

var brPassport = require('../lib/passport.js');

var HttpSignatureStrategy = require('../lib/HttpSignatureStrategy');
var signatureStrategy = new HttpSignatureStrategy();
bedrock.events.on('bedrock-express.configure.routes', addMockRoutes);

bedrock.start();

function addMockRoutes(app) {
  console.log('$@#@$@#@#$ Adding mock routes');
  var mockData = require('../tests/mock.data');
  app.get('/tests/bedrock-passport/http-signature-test',
    rest.when.prefers.jsonld,
    rest.linkedDataHandler({
      get: function(req, res, callback) {
        console.log('====== Signature authenticate called =========');
        signatureStrategy.authenticate(req);
        brPassport.authenticate('signature', {}, function(err, results) {
          callback(null, results);
        });
      }
    })
  );
  app.get('/keys/1.1.56.1',
    rest.when.prefers.jsonld,
    rest.linkedDataHandler({
      get: function(req, res, callback) {
        console.log('===== KEYS MOCK DATA ENDPOINT HIT ====');
        var key = mockData.key;
        callback(null, key);
      }
    })
  );
  app.get('/i/mock',
    rest.when.prefers.jsonld,
    rest.linkedDataHandler({
      get: function(req, res, callback) {
        var owner1 = mockData.owner1;
        callback(null, owner1);
      }
    })
  );
  /*
  app.get('/tests/bedrock-passport/owner2',
    rest.when.prefers.jsonld, brPassport.optionallyAuthenticated,
    rest.linkedDataHandler({
      get: function(req, res, callback) {
        var owner2 = mockData.owner2;
        callback(null, owner2);
      }
    })
  );*/
}
