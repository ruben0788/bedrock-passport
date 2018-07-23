const bedrock = require('bedrock');
const brPassport = require('bedrock-passport');
const rest = require('bedrock-rest');
const mockData = require('./mocha/mock.data');
const {BedrockError} = bedrock.util;

// TODO: probably want a middleware that checks the ocaps here...
// ... skipping the invocation check instead of this thing, the rest is
// automatic via http signatures...
const requireOcap = brPassport.createMiddleware({
  strategy: 'default',
  required: true,
  optionsMap: {
    'http-signature-strategy': {
      // TODO: this is for a failure case
      //keyType: 'CryptographicKey'
      ocapToResourceRoles({ocap}) {
        const resourceRoles = [];
        if(ocap.id === 'foo') {
          resourceRoles.push({
            sysRole: 'role-name',
            resource: 'resourceId'
          });
        }
        console.log('mapped to', resourceRoles);
        return resourceRoles;
      }
    }
  }
});

bedrock.events.on('bedrock-express.configure.routes', app => {
  app.get('/tests/bedrock-passport/http-signature-test',
    brPassport.ensureAuthenticated,
    rest.when.prefers.jsonld,
    rest.linkedDataHandler({
      get: (req, res, callback) => {
        callback(null, req.user);
      }
    })
  );
  app.get('/tests/bedrock-passport/http-signature-ocap-test',
    requireOcap,
    rest.when.prefers.jsonld,
    rest.linkedDataHandler({
      get: (req, res, callback) => {
        // TODO: check `req.user.actor` for resourceRole with
        // `role-name` and `resourceId`
        console.log('req.user.actor', req.user.actor.sysResourceRole);
        callback(null, req.user);
      }
    })
  );
  app.get('/keys/:key', rest.when.prefers.jsonld, rest.linkedDataHandler({
    get: (req, res, callback) => {
      if(!mockData.keys[req.params.key]) {
        return callback(new BedrockError('Not Found.', 'NotFoundError', {
          public: true,
          httpStatusCode: 404
        }));
      }
      callback(null, mockData.keys[req.params.key]);
    }
  }));
  app.get('/tests/i/:owner', rest.when.prefers.jsonld, rest.linkedDataHandler({
    get: (req, res, callback) => {
      if(!mockData.owners[req.params.owner]) {
        return callback(new BedrockError('Not Found.', 'NotFoundError', {
          public: true,
          httpStatusCode: 404
        }));
      }
      callback(null, mockData.owners[req.params.owner]);
    }
  }));
});
