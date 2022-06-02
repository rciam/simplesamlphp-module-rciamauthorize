# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Fixed

- Fix naming of configuration parameters
- Add support for keycloak

## [v2.1.1] - 2021-11-29

### Fixed

- `OIDCAuhtorize` should use RelayState instead of requesterID and extract the client ID
- Increase logging when access is forbidden

## [v2.1.0] - 2021-07-08

### Added

- Add `OIDCAuhtorize` authentication processing filter to support user authorisation for OpenID Connect clients based on attribute matching

## [v2.0.0] - 2021-03-01

This version is compatible with [SimpleSAMLphp v1.17](https://simplesamlphp.org/docs/1.17/simplesamlphp-changelog)

### Changed

- Comply to [PSR-4: Autoloader](https://www.php-fig.org/psr/psr-4/) guidelines
- Comply to [PSR-1: Basic Coding Standard](https://www.php-fig.org/psr/psr-1/) guidelines
- Comply to [PSR-12: Extended Coding Style](https://www.php-fig.org/psr/psr-12/) guidelines
- Apply modern array syntax to comply with [SimpleSAMLphp v1.17](https://simplesamlphp.org/docs/stable/simplesamlphp-upgrade-notes-1.17)

## [v1.0.0] - 2021-03-01

This version is compatible with [SimpleSAMLphp v1.14](https://simplesamlphp.org/docs/1.14/simplesamlphp-changelog)

### Added

- Authproc filter `rciamauthorize:Authorize` for attribute-based access control
