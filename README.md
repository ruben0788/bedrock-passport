# bedrock-passport

A [bedrock][] module that adds website or REST API authentication to
[bedrock][] via [passport][].

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
    res.status(204).end();
  });
```

## Configuration

For documentation on configuration, see [config.js](./lib/config.js).

## Authentication

There are a number of ways a client may authenticate itself with the REST API.
These methods include:

- Website session based on user and password and using cookies.
- [HTTP Signatures][]

### Cookies

This method of authentication is useful for clients that are under your control
and who you trust with your password to the service.

### HTTP Signatures

[HTTP Signatures][]-based authentication which is useful for non-interactive
clients, and clients that you do not want to provide a password for.

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
