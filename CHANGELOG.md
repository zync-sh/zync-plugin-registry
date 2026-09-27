# Changelog

## Unreleased

### Added

- Optional HTTPS thumbnail URLs in registry inputs and release descriptors, validated and included in signed metadata.
- PM2's version-tagged public thumbnail for marketplace cards before installation.
- Regression coverage for thumbnail metadata assembly.

These publication-input changes take effect after the signed registry publication workflow runs; existing signed metadata is unchanged.
