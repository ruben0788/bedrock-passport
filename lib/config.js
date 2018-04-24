/*!
 * Bedrock passport configuration.
 *
 * Copyright (c) 2012-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const config = bedrock.config;
const cc = bedrock.util.config.main.computer();

config.passport = {};
config.passport.identity = {};
config.passport.identity.allowNonPersistent = true;
config.passport.initialize = {};
config.passport.strategies = {};

config.passport.strategies.signature = {};
config.passport.strategies.signature.disabled = false;
config.passport.strategies.signature.dereferenceUrlScheme = {
  did: true,
  https: true
};
config.passport.strategies.signature.strictSSLEnabled = false;

config.passport.strategies.did = {};
config.passport.strategies.did.disabled = false;
cc('passport.strategies.did.didio.baseUrl',
  () => config['did-client']['authorization-io'].didBaseUrl + '/');
