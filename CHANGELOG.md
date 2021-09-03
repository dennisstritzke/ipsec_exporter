# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),

## [Unreleased](https://github.com/dennisstritzke/ipsec_exporter/compare/v0.4.0...HEAD)

## [0.4.0](https://github.com/dennisstritzke/ipsec_exporter/releases/tag/v0.4.0) - 2021-09-03
### Added
- `--enable.sudo` command line options, which causes the exporter to prefix the `ipsec statusall`-call with `sudo`. (#23)

### Changed
- A tunnel is considered up, if the ipsec status output contains `REKEYED` or `REKEYING`.

## [0.3.2](https://github.com/dennisstritzke/ipsec_exporter/releases/tag/v0.3.2) - 2021-01-30
### Changed
- The release archive naming scheme matches those of other exporters like the Node Exporter: the archive contains a
  directory, which in turn contains the `ipsec_exporter` binary. The archive name drops the `v` prefix of the version.
- The `--web.listen-address` accepts a string instead of an int, which enables you to listen on specific interfaces. To
  preserve the previous behaviour the default is set to `0.0.0.0:9536`.

## [0.3.1](https://github.com/dennisstritzke/ipsec_exporter/releases/tag/v0.3.1) - 2019-05-02
### Changed
- The exporter drops comments found in the `ipsec.conf`

### Fixed
- Previously connection names containing a dot were cut off just before the dot.

## [0.3](https://github.com/dennisstritzke/ipsec_exporter/releases/tag/v0.3) - 2019-02-12
### Added
- This Changelog.
- Automated release process on Git Tag push.
- `--version` command line option.
- The exporter follows `include` directives in the IPsec config file and searches for connections in all referenced
  files.

### Changed
- The default listening port is now `9536` and registered as a [Prometheus Exporter Default port](https://github.com/prometheus/prometheus/wiki/Default-port-allocations).
  If you want to maintain the previous behaviour, launch the `ipsec_exporter` with the `--web.listen-address 9101`
  command line flag.
- Requesting the exporters `/` page now displays a HTML page instead of the previous redirect to `/metrics`.
- Renamed the `--collector.ipsec.conf` command line flag to `config-path`.

## [0.2](https://github.com/dennisstritzke/ipsec_exporter/releases/tag/v0.2) - 2018-07-30
### Added
- Connections containing `auto=ignored` are reported as ignored (ipsec_status = 4)

## [0.1.2.1](https://github.com/dennisstritzke/ipsec_exporter/releases/tag/v0.1.2.1) - 2018-06-05
### Fixed
- Concurrent read and write operations on map containing the IPsec configuration.

## [0.1.2](https://github.com/dennisstritzke/ipsec_exporter/releases/tag/v0.1.2) - 2018-05-09
### Added
- Support for connection names that contain numbers.

### Changed
- Golang dependency management to [Glide](https://github.com/Masterminds/glide). 

## [0.1.1](https://github.com/dennisstritzke/ipsec_exporter/releases/tag/v0.1.1) - 2018-01-29
### Added
- Checking, if the config file provided is readable.

### Changed
- Warns, if there are no connections configured in the IPsec config file. 
- Warns, if IPsec status couldn't be determined for a connection.

## [0.1](https://github.com/dennisstritzke/ipsec_exporter/releases/tag/v0.1) - 2018-01-28 
### Added
- Detection of configured IPsec tunnels by reading the `ipsec.conf` file.
- Prometheus metrics, indicate if the tunnel is up, the connection is up or the tunnel is down.
