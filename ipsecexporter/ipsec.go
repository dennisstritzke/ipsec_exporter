package ipsecexporter

import (
	"strings"
	"regexp"
	"os/exec"
	"bytes"
	"strconv"
	"io/ioutil"
	"github.com/prometheus/common/log"
)

type IpSecConfiguration struct {
	tunnel []string
}

type IpSecStatus struct {
	status map[string]int
}

const (
	tunnelInstalled       int = 0
	connectionEstablished int = 1
	down                  int = 2
	unknown               int = 3
)

func FetchIpSecConfiguration(fileName string) (IpSecConfiguration, error) {
	content, err := loadConfig(fileName)
	connectionNames := getConfiguredIpSecConnection(extractLines(content))

	return IpSecConfiguration{
		tunnel: connectionNames,
	}, err
}

func (c IpSecConfiguration) QueryStatus() IpSecStatus {
	s := IpSecStatus{
		status: map[string]int{},
	}

	for _, connection := range c.tunnel {
		cmd := exec.Command("ipsec", "status", connection)
		if out, err := cmd.Output(); err != nil {
			log.Warnf("Were not able to execute 'ipsec status %s'. %v", connection, err)
			continue
		} else {
			status := getStatus(out)
			s.status[connection] = status
		}
	}

	return s
}

func (s IpSecStatus) PrometheusMetrics() string {
	var buffer bytes.Buffer

	buffer.WriteString("# HELP ipsec_status parsed ipsec status output\n")
	buffer.WriteString("# TYPE ipsec_status untyped\n")

	for connection := range s.status {
		buffer.WriteString(`ipsec_status{tunnel="` + connection + `"} ` + strconv.Itoa(s.status[connection]) + "\n")
	}

	return buffer.String()
}

func getStatus(statusLine []byte) int {
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

func loadConfig(fileName string) (string, error) {
	buf, err := ioutil.ReadFile(fileName)
	if err != nil {
		return "", err
	}
	s := string(buf)
	return s, nil
}

func getConfiguredIpSecConnection(ipsecConfigLines []string) []string {
	connectionNames := []string{}

	for _, line := range ipsecConfigLines {
		re := regexp.MustCompile(`conn\s([a-zA-Z0-9_-]+)`)
		match := re.FindStringSubmatch(line)
		if len(match) >= 2 {
			connectionNames = append(connectionNames, match[1])
		}
	}

	return connectionNames
}

func extractLines(ipsecConfig string) []string {
	return strings.Split(ipsecConfig, "\n")
}
