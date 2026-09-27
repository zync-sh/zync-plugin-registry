# Changelog

## Unreleased

### Fixed

- Allow thumbnail-only updates to existing registry releases without weakening immutable package identity, trust metadata, or cumulative revocation preservation.

### Added

- Input-driven signed ZIP asset names and generic archive verification, removing PM2-specific release preparation rules.
- Docker Manager 0.2.0 release input and approval using the existing publisher key.
- Regression coverage for generic signed packages, unsafe archive paths and invalid release asset names.
- Optional HTTPS thumbnail URLs in registry inputs and release descriptors, validated and included in signed metadata.
- PM2's version-tagged public thumbnail for marketplace cards before installation.
- Regression coverage for thumbnail metadata assembly.

These publication-input changes take effect after the signed registry publication workflow runs; existing signed metadata is unchanged.
