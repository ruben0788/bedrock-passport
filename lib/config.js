/*!
 * Bedrock passport configuration.
 *
 * Copyright (c) 2012-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {config} = require('bedrock');

config.passport = {};
config.passport.identity = {};
config.passport.identity.allowNonPersistent = true;
config.passport.initialize = {};
config.passport.strategies = {};
