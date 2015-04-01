# bedrock-passport

A [bedrock][] module that adds website or REST API authentication to
[bedrock][] via [passport][].

Authentication methods supported:
- Website session based on user and password.
- [HTTP Signatures][].

## Quick Examples

```
npm install bedrock-passport
```

```js
var brPassport = require('bedrock-passport');

app.server.post('/resources/:resourceId',
  ensureAuthenticated,
  function(req, res, next) {
    // resourceId available with req.params.resourceId
    // user identity available with req.user.identity
    res.sendStatus(204);
  });
```

## Configuration

For documentation on configuration, see [config.js](./lib/config.js).

## API

### checkAuthentication(req, res, callback(err, info))

Check authentication of a request. If more than one authentication method is
present, all of the associated identities must match.

### optionallyAuthenticated(req, res, next)

Process a request has been optionally authenticated via `checkAuthentication`.
Code using this call can check if the request is authenticated by testing if
`req.user` and `req.user.identity` are set.

### ensureAuthenticated(req, res, next)

Ensure a request has been authenticated via `optionallyAuthenticated`. Redirect
if not and it looks like a browser GET request, otherwise set a 400 error.

### login(req, res, next, callback(err, user, choice))

Attempt to establish an authorized session for the user that sent the request.

[bedrock]: https://github.com/digitalbazaar/bedrock
[passport]: https://github.com/jaredhanson/passport
[HTTP Signatures]: https://web-payments.org/specs/source/http-signatures/
