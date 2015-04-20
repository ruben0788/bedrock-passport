/*
 * Copyright (c) 2012-2015 Digital Bazaar, Inc. All rights reserved.
 */
var async = require('async');
var bedrock = require('bedrock');
var brIdentity = require('bedrock-identity');
var util = require('util');
var LocalStrategy = require('passport-local');

// export strategy
module.exports = Strategy;

/**
 * Creates a new PasswordStrategy for use with passport.
 *
 * @param options the options to pass to the parent LocalStrategy.
 */
function Strategy(options) {
  LocalStrategy.Strategy.call(
    this, options, function(identifier, password, callback) {
    async.waterfall([
      function(callback) {
        brIdentity.resolveIdentityIdentifier(identifier, callback);
      },
      function(identityIds, callback) {
        // try to authenticate each possible identity ID
        var matches = [];
        async.forEach(identityIds, function(id, callback) {
          brIdentity.verifyIdentityPassword({
            id: id,
            sysPassword: password
          }, function(err, verified) {
            if(err) {
              return callback(err);
            }
            if(verified) {
              matches.push(id);
            }
            callback();
          });
        }, function(err) {
          callback(err, matches);
        });
      }
    ], function(err, matches) {
      if(err) {
        return callback(err);
      }
      if(matches.length === 0) {
        return callback(null, false, {message: 'Invalid login credentials.'});
      }
      // multiple identities authenticated, simply pass (do not do success)
      if(matches.length > 1) {
        return callback(null, false, {
          message: 'Multiple identity matches.',
          email: identifier,
          matches: matches
        });
      }
      // single identity match, populate and return success
      if(matches.length === 1) {
        // look up identity
        var actor = {id: matches[0]};
        async.auto({
          getIdentity: function(callback) {
            brIdentity.getIdentity(actor, matches[0], function(err, identity) {
              callback(err, identity);
            });
          }
        }, function(err, results) {
          callback(err, {identity: results.getIdentity});
        });
      }
    });
  });
  this.name = 'bedrock.password';
}
util.inherits(Strategy, LocalStrategy.Strategy);
