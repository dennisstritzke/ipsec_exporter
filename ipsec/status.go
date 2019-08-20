package ipsec

import (
	"github.com/prometheus/common/log"
	"os/exec"
	"os/user"
	"regexp"
	"strconv"
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
)

type statusProvider interface {
	statusOutput(tunnel connection) (string, error)
}

type cliStatusProvider struct {
}

func (c *cliStatusProvider) statusOutput(tunnel connection) (string, error) {
        var args [3]string

        user, _ := user.Current()

        if user.Username != "root" {
                args[0] = "/bin/sh"
                args[1] = "-c"
                args[2] = "sudo ipsec statusall " + tunnel.name
        } else {
                args[0] = "ipsec"
                args[1] = "statusall"
                args[2] = tunnel.name
        }

        cmd := exec.Command(args[0], args[1], args[2])
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
				up:         true,
				status:     extractStatus([]byte(out)),
				bytesIn:    extractIntWithRegex(out, `([[0-9]+) bytes_i`),
				bytesOut:   extractIntWithRegex(out, `([[0-9]+) bytes_o`),
				packetsIn:  extractIntWithRegex(out, `bytes_i \(([[0-9]+) pkts`),
				packetsOut: extractIntWithRegex(out, `bytes_o \(([[0-9]+) pkts`),
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
