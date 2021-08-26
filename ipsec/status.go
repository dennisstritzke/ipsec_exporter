package ipsec

import (
	"os/exec"
	"regexp"
	"strconv"

	"github.com/prometheus/common/log"
)

type status struct {
	up         bool
	status     connectionStatus
	bytesIn    int
	bytesOut   int
	packetsIn  int
	packetsOut int
}

type connectionStatus int

const (
	tunnelInstalled       connectionStatus = 0
	connectionEstablished connectionStatus = 1
	down                  connectionStatus = 2
	unknown               connectionStatus = 3
	ignored               connectionStatus = 4

	pseudoTunnelID = "0"
)

type statusProvider interface {
	statusOutput(tunnel connection) (string, error)
}

type cliStatusProvider struct {
}

func (c *cliStatusProvider) statusOutput(tunnel connection) (string, error) {
	cmd := exec.Command("ipsec", "statusall", tunnel.name)
	out, err := cmd.Output()

	if err != nil {
		return "", err
	}

	return string(out), nil
}

func queryStatus(ipSecConfiguration *Configuration, provider statusProvider) map[string]map[string]*status {
	statusMap := map[string]map[string]*status{}

	for _, connection := range ipSecConfiguration.tunnel {
		statusMap[connection.name] = make(map[string]*status)

		if connection.ignored {
			statusMap[connection.name][pseudoTunnelID] = &status{
				up:     true,
				status: ignored,
			}
			continue
		}

		if out, err := provider.statusOutput(connection); err != nil {
			log.Warnf("Unable to retrieve the status of tunnel '%s'. Reason: %v", connection.name, err)
			statusMap[connection.name][pseudoTunnelID] = &status{
				up:     false,
				status: unknown,
			}
		} else {
			for k := range extractTunnelInstances(out, connection) {
				tunnelInstanceStatistics := extractTunnelInstanceStatistics(out, fullTunnelInstanceName(connection, k))

				tunnelInstanceStatistics.up = true
				tunnelInstanceStatistics.status = extractStatus([]byte(out), connection, k)

				statusMap[connection.name][k] = &tunnelInstanceStatistics
			}
		}
	}

	return statusMap
}

func extractTunnelInstances(statusLine string, conn connection) map[string]struct{} {
	regex := regexp.MustCompile(conn.name + `{([0-9]+)}`)

	instances := map[string]struct{}{}

	for _, match := range regex.FindAllStringSubmatch(statusLine, -1) {
		if _, ok := instances[match[1]]; !ok {
			instances[match[1]] = struct{}{}
		}
	}

	if len(instances) == 0 {
		instances[pseudoTunnelID] = struct{}{}
	}

	return instances
}

func fullTunnelInstanceName(conn connection, instance string) string {
	return regexp.QuoteMeta(conn.name + "{" + instance + "}")
}

func extractStatus(statusLine []byte, conn connection, instance string) connectionStatus {
	noMatchRegex := regexp.MustCompile(`no match`)
	connectionEstablishedRegex := regexp.MustCompile(`\[[0-9]+]: *ESTABLISHED`)

	fullTunnelInstanceName := fullTunnelInstanceName(conn, instance)
	tunnelEstablishedRegex := regexp.MustCompile(fullTunnelInstanceName + `: *INSTALLED`)

	if connectionEstablishedRegex.Match(statusLine) {
		if tunnelEstablishedRegex.Match(statusLine) {
			return tunnelInstalled
		} else {
			return connectionEstablished
		}
	} else if noMatchRegex.Match(statusLine) {
		return down
	}

	return unknown
}

func extractTunnelInstanceStatistics(input, tunnel string) status {
	regex := regexp.MustCompile(tunnel + `:[^\n]+ ([0-9]+) bytes_i(?: \(([0-9]+) pkts?[^\n]+|), ([0-9]+) bytes_o(?: \(([0-9]+) pkts?|)`)

	var (
		counters [4]int
	)

	if match := regex.FindStringSubmatch(input); len(match) >= 5 {
		for idx, in := range match[1:] {
			if in == "" {
				counters[idx] = 0
				continue
			}
			num, err := strconv.Atoi(in)
			if err != nil {
				return status{}
			}
			counters[idx] = num
		}

		return status{
			bytesIn:   counters[0],
			packetsIn: counters[1],

			bytesOut:   counters[2],
			packetsOut: counters[3],
		}
	}

	return status{}
}
