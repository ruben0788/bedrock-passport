/*
 * Bedrock passport configuration.
 *
 * Copyright (c) 2012-2015 Digital Bazaar, Inc. All rights reserved.
 */
var config = require('bedrock').config;

config.passport = {};
config.passport.initialize = {};
config.passport.strategies = {};

config.passport.strategies.signature = {};
config.passport.strategies.signature.disabled = false;
config.passport.strategies.signature.dereferenceUrlScheme = {
  did: true,
  http: false,
  https: false
};

config.passport.strategies.did = {};
config.passport.strategies.did.disabled = false;
config.passport.strategies.did.didio = {};
config.passport.strategies.did.didio.baseUrl =
  'https://authorization.dev:33443/dids/';
