package ipsec

import (
	"github.com/prometheus/common/log"
	"os/exec"
	"regexp"
)

type status struct {
	status map[string]int
}

const (
	tunnelInstalled       int = 0
	connectionEstablished int = 1
	down                  int = 2
	unknown               int = 3
	ignored               int = 4
)

func queryStatus(ipSecConfiguration *Configuration) status {
	s := status{
		status: map[string]int{},
	}

	for _, connection := range ipSecConfiguration.tunnel {
		if connection.ignored {
			s.status[connection.name] = ignored
			continue
		}

		cmd := exec.Command("ipsec", "status", connection.name)
		if out, err := cmd.Output(); err != nil {
			log.Warnf("Were not able to execute 'ipsec status %s'. %v", connection, err)
			s.status[connection.name] = unknown
		} else {
			status := extractStatus(out)
			s.status[connection.name] = status
		}
	}

	return s
}

func extractStatus(statusLine []byte) int {
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
