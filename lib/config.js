/*
 * Bedrock passport configuration.
 *
 * Copyright (c) 2012-2015 Digital Bazaar, Inc. All rights reserved.
 */
var config = require('bedrock').config;

config.passport = {};
config.passport.authentication = {};
config.passport.authentication.httpSignature = {};
config.passport.authentication.httpSignature.enabled = true;
