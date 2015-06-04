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
