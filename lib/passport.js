/*
 * Copyright (c) 2012-2015 Digital Bazaar, Inc. All rights reserved.
 */
var _ = require('lodash');
var async = require('async');
var bedrock = require('bedrock');
var brIdentity = require('bedrock-identity');
var passport = require('passport');
var BedrockError = bedrock.util.BedrockError;
var DidStrategy = require('./DidStrategy');
var HttpSignatureStrategy = require('./HttpSignatureStrategy');
var URL = require('url');

// load config defaults
require('./config');

// configure for tests
bedrock.events.on('bedrock.test.configure', function() {
  require('./test.config');
});

// module API
var api = {};
module.exports = api;

// expose passport
api.passport = passport;

// registered strategies
var strategies = {};

// permitted CORS methods w/session authentication
var permittedCorsMethods = ['GET', 'HEAD', 'OPTIONS'];

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
  if(name in strategies) {
    throw new Error('"' + options.strategy.name + '" already registered.');
  }
  strategies[name] = options;
  // `session` strategy is built into passport by default
  if(name !== 'session') {
    passport.use(options.strategy);
  }
};

/**
 * Returns express middleware that will authenticate a request using the given
 * `strategy`. The event `bedrock-passport.authenticate` will be emitted
 * with the strategy, options, and user information.
 *
 * @param strategy the name of the strategy to use.
 * @param [options] the options to use.
 * @param callback(err, user, info) the callback to call once authentication
 *          has been attempted.
 *
 * @return the middleware express route that is expecting a request, response,
 *           and next middleware function.
 */
api.authenticate = function(strategy, options, callback) {
  if(typeof options === 'function') {
    callback = options;
    options = {};
  }
  options = options || {};
  // handle built-in session-based authentication
  if(strategy === 'session') {
    return function(req, res, next) {
      // restrict session-based authentication to when:
      // 1. There is no origin header set.
      // 2. The origin header matches the host header.
      // 3. The request method is in a list of default permitted CORS methods.
      // TODO: add an option to allow controlling permittedCorsMethods for
      // particular handlers that know what they're doing
      var origin = ('origin' in req.headers ?
        URL.parse(req.headers.origin).host : null);
      if(origin === null || req.headers.host === origin ||
        permittedCorsMethods.indexOf(req.method) !== -1 ||
        _checkAllowedHosts(origin, options.allowHosts)) {
        if(options.allowUrlEncoded || !(
          req.is('urlencoded') || req.is('multipart'))) {
          // reuse existing check (express auto-runs a session check per
          // code below with `app.use(api.authenticate('session', ...))`
          // TODO: potentially refactor to avoid this auto-check in the future,
          // but it would be a breaking change
          // FIXME: `req.isAuthenticated` is not granular enough to determine
          // if `session` strategy was responsible for authentication, so
          // a degenerate case where a use was authenticated via another method
          // and then checked against session will pass when it should
          // potentially fail (no use case for this behavior, but this should
          // be fixed)
          if(options.reuse && req.isAuthenticated()) {
            return callback(null, req.user);
          }
          return passport.authenticate('session', options, done)(
            req, res, next);
        }
      }
      if(callback) {
        return callback(null, false);
      }
      next();
    };
  }

  // handle non-built-in strategies
  return passport.authenticate(strategy, options, done);

  function done(err, user, info) {
    if(!err && user) {
      return bedrock.events.emit('bedrock-passport.authenticate', {
        strategy: strategy,
        options: options,
        user: user,
        info: info
      }, function(err) {
        callback(err, user, info);
      });
    }
    callback(err, user, info);
  }
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
 * @param [options] options to use:
 *          [allowUrlEncoded] true to permit session-based authentication on
 *            requests that contain URL-encoded content; this is off by default
 *            to prevent CSRFs and if this is enabled it must be combined with
 *            CSRF protections (eg: CSRF tokens).
 *          [allowHosts] a list of cross-domain hosts to allow, '*' for any.
 * @param callback(err, result) called with error or null and the
 *          found auth info as {strategies: {}, user: identity} or false.
 */
api.checkAuthentication = function(req, res, options, callback) {
  if(typeof options === 'function') {
    callback = options;
    options = {};
  }

  var result = {};

  // try all strategies in parallel
  var parallel = Object.keys(strategies).map(function(name) {
    var strategy = strategies[name];
    var config = bedrock.config.passport.strategies[name] || {};
    return function(callback) {
      // skip check if not auto or 'disabled' flag is set for the strategy
      if(!strategy.auto || config.disabled) {
        return callback(null, false);
      }
      var strategyOptions = _.assign({}, strategy.options || {});
      if(name === 'session') {
        // reuse built-in check
        strategyOptions.reuse = true;
      }
      api.authenticate(name, strategyOptions, function(err, user) {
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
 * Process a request that has been optionally authenticated. Code using this
 * call can check if the request is authenticated by testing if req.user and
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

/**
 * Create an authenticator to ensure a request has been authenticated.
 *
 * @param [options] the options to use.
 *          [allowUrlEncoded] true to permit session-based authentication on
 *            requests that contain URL-encoded content; this is off by default
 *            to prevent CSRFs and if this is enabled it must be combined with
 *            CSRF protections (eg: CSRF tokens).
 *          [allowHosts] a list of cross-domain hosts to allow, '*' for any.
 *          [optional] true to only optionally authenticate.
 */
api.createAuthenticator = function(options) {
  options = options || {};
  return function(req, res, next) {
    api.checkAuthentication(req, res, options, function(err, info) {
      if(err) {
        return next(err);
      }
      // if authorization found, set req.user
      if(info) {
        req.user = info.user;
      }
      if(req.user || options.optional) {
        return next();
      }
      // not authenticated
      next(new BedrockError(
        'Not authenticated.', 'PermissionDenied',
        {'public': true, httpStatusCode: 400}));
    });
  };
};

// configure passport before serving static files
bedrock.events.on('bedrock-express.configure.static', function configure(app) {
  // TODO: add configuration options for default persistence of identity
  // information

  // define passport user serialization
  passport.serializeUser(function(user, callback) {
    /* Note: Here we take `user` from an authentication method and specify
    the object that will be persisted in the session database. The `identity`
    property in `user` is given special treatment. If `identity` has an `id`
    property that can be retrieved via `bedrock-identity`, then we only
    store the `id` in the session database and rely on persistent storage
    of the identity in `bedrock-identity` for later retrieval. If there is
    no such identity in `bedrock-identity`, then we assume we have a
    non-persistent identity and we cache everything about that identity in
    the session database. Once the session is gone, that information will
    also be gone. */

    // TODO: optimize to existence check only
    brIdentity.get(null, user.identity.id, function(err) {
      if(err) {
        if(err.name === 'NotFound') {
          // non-persistent user authenticated, persist entire user in session
          return callback(null, user);
        }
        return callback(err);
      }
      // only persist identity ID, rest of identity persisted by
      // `bedrock-identity`
      callback(err, _.assign({}, user, {identity: user.identity.id}));
    });
  });
  passport.deserializeUser(function(data, callback) {
    /* Note: Here we specify how to populate the `req.body.user` property
    used by express routes using information from the session. The `data`
    object was populated with whatever information was previously stored in
    the session database for the current session ID. If the `identity` property
    is not a string in the data, we simply return the data in the session
    database as-is. Otherwise, we look to see if the `identity` is an ID that
    refers to a persistent user that can be retrieved via `bedrock-identity`.
    If so, we replace the `data.identity` with that value and then return
    `data`. If not, we return `data` as-is. */

    // no identity or non-persistent identity
    if(typeof data.identity !== 'string') {
      return callback(null, data);
    }
    // look up persistent identity
    var actor = {id: data.identity};
    brIdentity.get(actor, data.identity, function(err, identity) {
      if(err) {
        return callback(err);
      }
      callback(null, _.assign({}, data, {identity: identity}));
    });
  });

  // init and attach passport
  app.use(passport.initialize(bedrock.config.passport.initialize));

  // special-register built-in session authentication to always run
  app.use(api.authenticate('session'));
  api.use({
    strategy: {name: 'session'},
    auto: true
  });

  // register default authentication strategies
  api.use({
    strategy: new HttpSignatureStrategy(),
    auto: true
  });
  api.use({
    strategy: new DidStrategy(),
    auto: false
  });
});

function _checkAllowedHosts(host, allowed) {
  if(!allowed) {
    return false;
  }
  if(!Array.isArray(allowed)) {
    allowed = [allowed];
  }
  return (allowed.indexOf('*') !== -1 || allowed.indexOf(host) !== -1);
}
