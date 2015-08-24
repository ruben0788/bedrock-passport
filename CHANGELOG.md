# bedrock-passport ChangeLog

## [Unreleased]

### Added
- Minor CSRF protections. When using authentication middleware, session-based
  authentication will only be counted as valid under certain conditions. If
  the request does not contain a urlencoded (single or multipart) body
  (unless explicitly permitted via the middleware options) it will not be
  counted. If an `Origin` header is in the request but its host value does not
  match the `Host` header and the method is not GET, HEAD, or OPTIONS, it will
  not be counted.

## [1.0.1] - 2015-05-07

## [1.0.0] - 2015-04-08

## [0.1.1] - 2015-02-23

### Added
- Support for `bedrock-express` 0.2.x.

### Changed
- **BREAKING**: `bedrock.HttpSignatureStrategy.*` error types renamed to `HttpSignature.*`.

## 0.1.0 - 2015-02-16

- See git history for changes.

[Unreleased]: https://github.com/digitalbazaar/bedrock-passport/compare/1.0.1...HEAD
[1.0.1]: https://github.com/digitalbazaar/bedrock-passport/compare/1.0.0...1.0.1
[1.0.0]: https://github.com/digitalbazaar/bedrock-passport/compare/0.1.1...1.0.0
[0.1.1]: https://github.com/digitalbazaar/bedrock-passport/compare/0.1.0...0.1.1
