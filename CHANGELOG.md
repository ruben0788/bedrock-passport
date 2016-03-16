# bedrock-passport ChangeLog

## [Unreleased]

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

[Unreleased]: https://github.com/digitalbazaar/bedrock-passport/compare/3.0.1...HEAD
[3.0.1]: https://github.com/digitalbazaar/bedrock-passport/compare/3.0.0...3.0.1
[3.0.0]: https://github.com/digitalbazaar/bedrock-passport/compare/2.0.1...3.0.0
[2.0.1]: https://github.com/digitalbazaar/bedrock-passport/compare/2.0.0...2.0.1
[2.0.0]: https://github.com/digitalbazaar/bedrock-passport/compare/1.0.1...2.0.0
[1.0.1]: https://github.com/digitalbazaar/bedrock-passport/compare/1.0.0...1.0.1
[1.0.0]: https://github.com/digitalbazaar/bedrock-passport/compare/0.1.1...1.0.0
[0.1.1]: https://github.com/digitalbazaar/bedrock-passport/compare/0.1.0...0.1.1
