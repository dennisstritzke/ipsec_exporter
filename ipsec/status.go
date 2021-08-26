package ipsec

import (
	"github.com/prometheus/common/log"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

type counterStruct struct {
	bytesIn    int
	bytesOut   int
	packetsIn  int
	packetsOut int
}

type status struct {
	up     bool
	status connectionStatus
	//counterStruct
	bytesIn     int
	bytesOut    int
	packetsIn   int
	packetsOut  int
	spiCounters map[string]counterStruct
}

type connectionStatus int

const (
	tunnelInstalled       connectionStatus = 0
	connectionEstablished connectionStatus = 1
	down                  connectionStatus = 2
	unknown               connectionStatus = 3
	ignored               connectionStatus = 4
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

func queryStatus(ipSecConfiguration *Configuration, provider statusProvider) map[string]*status {
	statusMap := map[string]*status{}

	for _, connection := range ipSecConfiguration.tunnel {
		if connection.ignored {
			statusMap[connection.name] = &status{
				up:     true,
				status: ignored,
			}
			continue
		}

		if out, err := provider.statusOutput(connection); err != nil {
			log.Warnf("Unable to retrieve the status of tunnel '%s'. Reason: %v", connection.name, err)
			statusMap[connection.name] = &status{
				up:     false,
				status: unknown,
			}
		} else {
			statusMap[connection.name] = &status{
				up:          true,
				status:      extractStatus([]byte(out)),
				bytesIn:     extractIntWithRegex(out, `([[0-9]+) bytes_i`),
				bytesOut:    extractIntWithRegex(out, `([[0-9]+) bytes_o`),
				packetsIn:   extractIntWithRegex(out, `bytes_i \(([[0-9]+) pkts`),
				packetsOut:  extractIntWithRegex(out, `bytes_o \(([[0-9]+) pkts`),
				spiCounters: extractPairCounters(out),
			}
		}
	}

	return statusMap
}

func extractStatus(statusLine []byte) connectionStatus {
	noMatchRegex := regexp.MustCompile(`no match`)
	tunnelEstablishedRegex := regexp.MustCompile(`{[0-9]+}: *INSTALLED`)
	connectionEstablishedRegex := regexp.MustCompile(`[[0-9]+]: *ESTABLISHED`)

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

func extractPairCounters(input string) map[string]counterStruct {
	var tunnelMark = regexp.MustCompile("TUNNEL.*SPIs")
	var spiPairMark = regexp.MustCompile(`(?P<pair>([0-9]+\.){3}[0-9]+(\/[0-9]+)? === ([0-9]+\.){3}[0-9]+(\/[0-9]+)?)`)
	var expectCounters bool = false
	var expectPair bool = false
	//var expectTunnel bool = true
	var bi int
	var bo int
	var pi int
	var po int
	var pair string
	var counters map[string]counterStruct = make(map[string]counterStruct)
	byLine := strings.Split(input, "\n")
	for _, a := range byLine {
		if len(tunnelMark.FindStringSubmatch(a)) > 0 {
			expectCounters = true
			continue
		}
		if expectCounters {
			bi = extractIntWithRegex(a, `([[0-9]+) bytes_i`)
			bo = extractIntWithRegex(a, `([[0-9]+) bytes_o`)
			pi = extractIntWithRegex(a, `bytes_i \(([[0-9]+) pkts`)
			po = extractIntWithRegex(a, `bytes_o \(([[0-9]+) pkts`)
			expectCounters = false
			expectPair = true
			continue
		}
		if expectPair && len(spiPairMark.FindStringSubmatch(a)) > 0 {
			m := spiPairMark.FindStringSubmatch(a)
			for i, n := range spiPairMark.SubexpNames() {
				if n == "pair" {
					pair = m[i]
					s := counterStruct{bytesIn: bi,
						bytesOut:   bo,
						packetsIn:  pi,
						packetsOut: po}
					counters[pair] = s
				}
			}
			bi = 0
			bo = 0
			pi = 0
			po = 0
			expectPair = false
			//expectTunnel = true
		}
	}
	return counters
}

func extractIntWithRegex(input string, regex string) int {
	re := regexp.MustCompile(regex)
	match := re.FindStringSubmatch(input)
	if len(match) >= 2 {
		i, err := strconv.Atoi(match[1])
		if err != nil {
			return 0
		}
		return i
	}

	return 0
}
