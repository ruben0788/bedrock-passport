/*!
 * Copyright (c) 2015-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const async = require('async');
const brKey = require('bedrock-key');
const brIdentity = require('bedrock-identity');
const config = require('bedrock').config;
const database = require('bedrock-mongodb');

const api = {};
module.exports = api;

api.createHttpSignatureRequest = (url, identity) => {
  const newRequest = {
    url: url,
    httpSignature: {
      key: identity.keys.privateKey.privateKeyPem,
      keyId: identity.keys.publicKey.id,
      headers: ['date', 'host', 'request-line']
    }
  };
  return newRequest;
};

api.createIdentity = userName => {
  const newIdentity = {
    id: 'https://' + config.server.host + '/tests/i/' + userName,
    type: 'Identity',
    sysSlug: userName,
    label: userName,
    email: userName + '@bedrock.dev',
    sysPassword: 'password',
    sysPublic: ['label', 'url', 'description'],
    sysResourceRole: [],
    url: config.server.baseUri,
    description: userName,
    sysStatus: 'active'
  };
  return newIdentity;
};

api.createKeyPair = options => {
  const userName = options.userName;
  const publicKey = options.publicKey;
  const privateKey = options.privateKey;
  let ownerId = null;
  const keyId = options.keyId;
  if(userName === 'userUnknown') {
    ownerId = '';
  } else {
    ownerId = options.userId;
  }
  const newKeyPair = {
    publicKey: {
      '@context': 'https://w3id.org/identity/v1',
      id: 'https://' + config.server.host + '/keys/' + keyId,
      type: 'CryptographicKey',
      owner: ownerId,
      label: 'Signing Key 1',
      publicKeyPem: publicKey
    },
    privateKey: {
      type: 'CryptographicKey',
      owner: ownerId,
      label: 'Signing Key 1',
      publicKey: 'https://' + config.server.host + '/keys/' + keyId,
      privateKeyPem: privateKey
    }
  };
  return newKeyPair;
};

api.prepareDatabase = (mockData, callback) => async.series([
  callback => api.removeCollections(callback),
  callback => insertTestData(mockData, callback)
], callback);

api.randomDate = (start, end) => {
  return new Date(
    start.getTime() + Math.random() * (end.getTime() - start.getTime()));
};

api.removeCollections = callback => {
  const collectionNames =
    ['credentialProvider', 'identity', 'publicKey', 'eventLog'];
  database.openCollections(collectionNames, err => {
    if(err) {
      return callback(err);
    }
    async.each(collectionNames, (collectionName, callback) =>
      database.collections[collectionName].remove({}, callback),
    err => callback(err));
  });
};

api.removeCollection = (collection, callback) => {
  const collectionNames = [collection];
  database.openCollections(collectionNames, err => {
    if(err) {
      return callback(err);
    }
    async.each(collectionNames, (collectionName, callback) =>
      database.collections[collectionName].remove({}, callback),
    err => callback(err));
  });
};

// Insert identities and public keys used for testing into database
function insertTestData(mockData, callback) {
  async.forEachOf(mockData.identities, (identity, key, callback) =>
    async.parallel([
      callback => brIdentity.insert(null, identity.identity, callback),
      callback => brKey.addPublicKey(null, identity.keys.publicKey, callback)
    ], callback),
  err => {
    if(err) {
      if(!database.isDuplicateError(err)) {
        // duplicate error means test data is already loaded
        return callback(err);
      }
    }
    callback();
  }, callback);
}
