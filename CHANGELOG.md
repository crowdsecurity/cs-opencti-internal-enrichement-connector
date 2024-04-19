# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## SemVer public API

The [public API](https://semver.org/spec/v2.0.0.html#spec-item-1)  for this project is defined by the set of 
functions provided by the `src` folder and the following files: `docker-compose.yml`, `Dockerfile`, `entrypoint.sh`

---

## [1.1.0](https://github.com/crowdsecurity/cs-opencti-internal-enrichment-connector/releases/tag/v1.1.0) - 2024-??-??
[_Compare with previous release_](https://github.com/crowdsecurity/cs-opencti-internal-enrichment-connector/compare/v1.0.0...v1.1.0)

### Changed

- Change default recommended name from `crowdsec` to `CrowdSec`
- Change CTI url to the console one

### Added

- Add notes in observable
- Add label types (`reputation`, `scenario`, `behavior`, `cve`, `mitre techniques` ) and associated colors
- And configurations to enable/disable each label type

---

## [1.0.0](https://github.com/crowdsecurity/cs-opencti-internal-enrichment-connector/releases/tag/v1.0.0) - 2024-04-19

- Initial release
