# IPsec Exporter ![Test](https://github.com/dennisstritzke/ipsec_exporter/workflows/Test/badge.svg)
Prometheus exporter for ipsec metrics, written in Go.

## Functionality
The IPsec exporter is determining the state of the configured IPsec tunnels via the following procedure.
1. Starting up the `ipsec.conf` is read. All tunnels configured via the `conn` keyword are observed.
1. If the `/metrics` endpoint is queried, the exporter calls `ipsec status <tunnel name>` for each configured
connection. The output is parsed.
    * If the output contains `ESTABLISHED`, we assume that only the connection is up.
    * If the output contains `INSTALLED`, we assume that the tunnel is up and running.
    * If the output contains `no match`, we assume that the connection is down.

## Value Definition
| Metric | Value | Description |
|--------|-------|-------------|
| ipsec_status | 0 | The connection is established and tunnel is installed. The tunnel is up and running. |
| ipsec_status | 1 | The connection is established, but the tunnel is not up. |
| ipsec_status | 2 | The tunnel is down. |
| ipsec_status | 3 | The tunnel is in an unknown state. |
| ipsec_status | 4 | The tunnel is ignored. |