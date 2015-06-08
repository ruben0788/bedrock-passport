/*
 * Copyright (c) 2012-2015 Digital Bazaar, Inc. All rights reserved.
 */
var async = require('async');
var bedrock = require('bedrock');
var brIdentity = require('bedrock-identity');
var passport = require('passport');
var BedrockError = bedrock.util.BedrockError;
var HttpSignatureStrategy = require('./HttpSignatureStrategy');

// load config defaults
require('./config');

// module API
var api = {};
module.exports = api;

// expose passport
api.passport = passport;

// registered strategies
var strategies = {};

/**
 * Registers a new passport strategy.
 *
 * @param options the options to use:
 *          strategy the strategy to use.
 *          [auto] true to automatically run authenticate.
 *          [options] the options to pass if auto-running authenticate.
 */
api.use = function(options) {
  if(!options || !options.strategy || !('name' in options.strategy)) {
    throw new Error('options.strategy must be a passport Strategy.');
  }
  var name = options.strategy.name;
  if(name in strategies || name === 'session') {
    throw new Error('"' + options.strategy.name + '" already registered.');
  }
  strategies[name] = options;
  passport.use(options.strategy);
};

/**
 * Checks authentication of a request using all registered strategies. The
 * results of each strategy will be included in the output.
 *
 * If more than one strategy was attempted, then the identity associated with
 * every attempted strategy must match, or an error will be raised.
 *
 * @param req the request.
 * @param res the response.
 * @param callback(err, result) called with error or null and the
 *          found auth info as {strategies: {}, user: identity} or false.
 */
api.checkAuthentication = function(req, res, callback) {
  var result = {};

  // detect use of built-in session strategy
  result.session = req.isAuthenticated() ? req.user : false;

  // try all strategies in parallel
  var parallel = Object.keys(strategies).map(function(name) {
    var strategy = strategies[name];
    var config = bedrock.config.passport.strategies[name] || {};
    return function(callback) {
      // skip check if not auto or 'disabled' flag is set for the strategy
      if(!strategy.auto || config.disabled) {
        return callback(null, false);
      }
      passport.authenticate(name, strategy.options || {}, function(err, user) {
        result[name] = err ? false : user;
        callback(err, user);
      })(req, res, function(err) {
        callback(err);
      });
    };
  });

  async.auto({
    auth: function(callback) {
      async.parallel(parallel, callback);
    },
    compare: ['auth', function(callback) {
      // ensure the same identity was used for every attempted strategy
      var user_ = false;
      for(var name in result) {
        var user = result[name];
        if(!user) {
          continue;
        }
        if(!user_) {
          user_ = user;
        } else if(user.identity.id !== user_.identity.id) {
          return callback(new BedrockError(
            'Request authentication mismatch.', 'PermissionDenied',
            {'public': true, httpStatusCode: 400}));
        }
      }
      callback(null, user_);
    }]
  }, function(err, results) {
    // 400 if there is an error
    if(err) {
      return callback(new BedrockError(
        'Request authentication error.', 'PermissionDenied',
        {'public': true, httpStatusCode: 400}, err));
    }
    callback(null, {strategies: result, user: results.compare});
  });
};

/**
 * Process a request has been optionally authenticated. Code using this call
 * can check if the request is authenticated by testing if req.user and
 * req.user.identity are set.
 *
 * @param req the request.
 * @param res the response.
 * @param next the next route handler.
 */
api.optionallyAuthenticated = function(req, res, next) {
  api.checkAuthentication(req, res, function(err, info) {
    if(err) {
      return next(err);
    }
    // if authorization found, set req.user
    if(info) {
      req.user = info.user;
    }
    next();
  });
};

/**
 * Ensure a request has been authenticated. Redirect if not and it looks like
 * a browser GET request, otherwise set 400 error.
 *
 * @param req the request.
 * @param res the response.
 * @param next the next route handler.
 */
api.ensureAuthenticated = function(req, res, next) {
  api.optionallyAuthenticated(req, res, function(err) {
    if(err) {
      return next(err);
    }
    // authenticated
    if(req.user) {
      return next();
    }
    // not authenticated
    next(new BedrockError(
      'Not authenticated.', 'PermissionDenied',
      {'public': true, httpStatusCode: 400}));
  });
};

// configure passport before serving static files
bedrock.events.on('bedrock-express.configure.static', function configure(app) {
  // define passport user serialization
  passport.serializeUser(function(user, callback) {
    // save identity ID
    callback(null, {identity: user.identity.id});
  });
  passport.deserializeUser(function(data, callback) {
    // look up identity
    var actor = {id: data.identity};
    async.auto({
      getIdentity: function(callback) {
        if(data.identity === null) {
          return callback(null, null);
        }
        brIdentity.get(actor, data.identity, function(err, identity) {
          if(err) {
            return callback(err);
          }
          callback(err, identity);
        });
      }
    }, function(err, results) {
      if(err) {
        return callback(err);
      }
      callback(null, {identity: results.getIdentity});
    });
  });

  // register default authentication strategies
  api.use({
    strategy: new HttpSignatureStrategy(),
    auto: true
  });

  // init and attach passport
  app.use(passport.initialize(bedrock.config.passport.initialize));
  app.use(passport.session());
});
