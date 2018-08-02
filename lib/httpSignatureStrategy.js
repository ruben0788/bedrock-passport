/*!
 * Copyright (c) 2013-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const brAccount = require('bedrock-account');
const brIdentity = require('bedrock-identity');
const brKey = require('bedrock-key');
const Middleware = require('http-signature-middleware');
const jsigs = require('jsonld-signatures')();
const {BedrockError} = bedrock.util;

const api = {};
module.exports = api;

api.strategy = new Middleware();
api.strategy.use('getKey', _getKey);
api.strategy.use('getUser', _getUser);
api.strategy.use('validateRequest', _validateRequest);
api.strategy.use(
  'validateCapabilityInvocations', _validateCapabilityInvocations);

bedrock.events.on('bedrock.init', () => {
  // configure local jsigs copy to use bedrock.jsonld
  jsigs.use('jsonld', bedrock.jsonld);
  api.strategy.use('jsigs', jsigs);
  api.strategy.dereferenceUrlScheme.did = async ({keyId}) => {
    return bedrock.jsonld.documentLoader(keyId);
  };
});

async function _getKey({keyId, req, parsed, options}) {
  try {
    const {publicKey} = await brKey.getPublicKey({publicKey: {id: keyId}});
    return publicKey;
  } catch(err) {
    if(err && err.name === 'NotFoundError') {
      // Retrieve the public key based on the ID's
      // URL scheme when we can't find it in our database.
      return api.strategy.ldGetKey.call(
        api.strategy, {keyId, req, parsed, options});
    }
    throw err;
  }
}

async function _getUser({req, keyDoc, options}) {
  const {owner} = keyDoc;
  let identityRecord;
  try {
    identityRecord = await brIdentity.get({actor: null, id: owner});
  } catch(err) {
    if(err.name === 'NotFoundError') {
      // fallback to basic non-persistent id
      const user = {
        id: owner,
        identity: {
          // TODO: determine if this context is necessary or implied
          '@context': bedrock.config.constants.SECURITY_CONTEXT_V2_URL,
          id: owner
        },
        actor: {
          id: owner,
          sysResourceRole: []
        }
      };
      _mapCapabilityInvocations({user, req, options});
      return user;
    }
    throw err;
  }

  const {identity, meta} = identityRecord;
  const user = {identity};

  // see if an account exists for the identity
  if(typeof meta['bedrock-account'] === 'object' &&
    typeof meta['bedrock-account'].account === 'string') {
    const id = meta['bedrock-account.account'];
    // identity is managed by `account`
    [user.account, user.actor] = await Promise.all([
      brAccount.get({actor: null, id}),
      brAccount.getCapabilities({id: user.account.id})]);
  } else {
    // no `account`, so create `actor` from identity
    user.actor = await brIdentity.getCapabilities({id: identity.id});
  }

  _mapCapabilityInvocations({user, req, options});

  return user;
}

async function _mapCapabilityInvocations({user, req, options}) {
  if(req.capabilityInvocations && req.capabilityInvocations.length > 0 &&
    typeof options.ocapToResourceRoles === 'function') {
    // `options.ocapToResourceRoles` outputs a promise that resolves to an
    // array; await all of those arrays and then flatten them into a single
    // array of resource roles, then push them all onto the actor
    const resourceRoles = [].concat(...await Promise.all(
      req.capabilityInvocations.map(capabilityInvocation =>
        options.ocapToResourceRoles({capabilityInvocation}))));
    if(resourceRoles) {
      user.actor.sysResourceRole.push(...resourceRoles);
    }
  }
}

async function _validateRequest({req, parsed, options}) {
  const host = req.header('host');
  if(host !== bedrock.config.server.host) {
    throw new BedrockError(
      'Host header contains an invalid host name.',
      'SyntaxError', {
        public: true,
        httpStatusCode: 400,
        headers: {host}
      });
  }
}

async function _validateCapabilityInvocations({req, parsed, options}) {
  // TODO: run ocapld.js to verify all ocaps retrieved
  // TODO: pass option to ocapld.js to use `getObjectCapability` when
  // ...fetching chains, ideally code is in http-signature-middleware and
  // we just call `api.strategy.validateOcapLd` here
}
