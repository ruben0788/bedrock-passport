# bedrock-passport ChangeLog

## 3.1.1 - 2016-05-19

### Fixed
- Fix bug w/improperly setting the shared `callback` closure var
  in `authenticate`.
- Fix passing strategy options when using `createAuthenticator`.

## 3.1.0 - 2016-05-13

### Added
- Optionally disable logins for non-persistent users.

## [3.0.5] - 2016-05-09

### Fixed
- Ensure `bedrock-passport.authenticate` is emitted when using session authN.

## [3.0.4] - 2016-04-28

## [3.0.3] - 2016-04-26

## [3.0.2] - 2016-04-15

### Changed
- Update bedrock dependencies.

## [3.0.1] - 2016-03-16

### Changed
- Add public key lookup for HTTPSignature keyIds that are dids.

## [3.0.0] - 2016-03-02

### Changed
- Update package dependencies for npm v3 compatibility.

## [2.0.1] - 2016-02-01

## Changed
- Support non-persistent users in HttpSignatureStrategy.

## [2.0.0] - 2016-01-31

### Changed
- **BREAKING**: Modular redesign.
- **BREAKING**: Better extensibility and configurability.

### Added
- Minor CSRF protections. When using authentication middleware, session-based
  authentication will only be counted as valid under certain conditions. If
  the request does not contain a urlencoded (single or multipart) body
  (unless explicitly permitted via the middleware options) it will not be
  counted. If an `Origin` header is in the request but its host value does not
  match the `Host` header and the method is not GET, HEAD, or OPTIONS, it will
  not be counted.
- Strategy for authenticating via DIDs.

## [1.0.1] - 2015-05-07

## [1.0.0] - 2015-04-08

## [0.1.1] - 2015-02-23

### Added
- Support for `bedrock-express` 0.2.x.

### Changed
- **BREAKING**: `bedrock.HttpSignatureStrategy.*` error types renamed to `HttpSignature.*`.

## 0.1.0 - 2015-02-16

- See git history for changes.
