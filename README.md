# Azul Plugin Report Feeds

This plugin downloads reports/blogs for use in Azul.

## Overview

This plugin is highly configurable with the sources it downloads configurable via a yaml file.
An example of that file can be seen in `azul_plugin_report_feeds/reportcollector/reportfeeds.yaml`.

When in use the plugin is run as a cronjob that runs every 4 hours as defined by the cronjob in azul-app.

When it runs it will go to each feed listed in the reportfeeds.yaml file and search for any new reports.
(The plugin stores the timestamp of the last report it downloaded for each feed.)
When it identifies a report it will search for malware samples, sha256's, md5's and sha1s.
If any are found it downloads the report or converts the webpage to a PDF as the report.

Once the `ReportResult` is provided from the ReportCollector to the plugin it will discard any hashes that don't
also include a sha256, because azul doesn't have a way of storing files without their id (sha256).

Once the report is collected the plugin will:

- Attach the report to a binary_enrichment event and submit it to dispatcher.
- Request to download all sha256's it found by submit download events that should be picked up by the virus-total plugin.
  That plugin will then download the file if they exist in VirusTotal.
- Upload found malware samples as binary_sourced events, it will also attach report to these sourced events.

To verify the plugin is running check the Grafana graph `report-feeds` which will show the status of each individual
feed and provide a summary of the Report feeds plugin.

## Development Installation

To install azul-plugin-report-feeds for development run the command
(from the root directory of this project):

```bash
pip install -e .
playwright install-deps
playwright install
```

## Usage: azul-plugin-report-feeds

Doesn't run locally like other plugins because it doesn't use the same run loop.

```bash
azul-plugin-report-feeds --server 'http://azul-dispatcher.local'
```

## Usage: reportcollector

Report collector can be run separately and will attempt to scrape report into and then download sha256's from
virustotal.

```bash
reportcollector --api="VTAPIKEY"
```

## Full list of report feeds

A full list of used report feeds can be found in
`azul_plugin_report_feeds/reportcollector/reportfeeds-full.yaml`.

## Python Package management

This python package is managed using a `pyproject.toml` file.

Standardisation of installing and testing the python package is handled through tox.
Tox commands include:

```bash
# Run all standard tox actions
tox
# Run linting only
tox -e style
# Run tests only
tox -e test
```

## Dependency management

Dependencies are managed in the pyproject.toml and debian.txt file.

Version pinning is achieved using the `uv.lock` file.
Because the `uv.lock` file is configured to use a private UV registry, external developers using UV will need to delete the existing `uv.lock` file and update the project configuration to point to the publicly available PyPI registry instead.

To add new dependencies it's recommended to use uv with the command `uv add <new-package>`
    or for a dev package `uv add --dev <new-dev-package>`

The tool used for linting and managing styling is `ruff` and it is configured via `pyproject.toml`

The debian.txt file manages the debian dependencies that need to be installed on development systems and docker images.

Sometimes the debian.txt file is insufficient and in this case the Dockerfile may need to be modified directly to
install complex dependencies.