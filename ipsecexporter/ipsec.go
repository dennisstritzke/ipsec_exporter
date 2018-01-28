package ipsecexporter

import (
	"io/ioutil"
	"strings"
	"regexp"
	"os/exec"
	"bytes"
	"strconv"
)

type IpSecStatus struct {
	status map[string]int
}

const (
	TUNNEL_INSTALLED       int = 0
	CONNECTION_ESTABLISHED int = 1
	DOWN                   int = 2
	UNKNOWN                int = 3
)

func CreateIpSecStatus(fileName string) (IpSecStatus, error) {
	ipsec := IpSecStatus{}
	ipsec.status = map[string]int{}

	content, err := loadConfig(fileName)
	connectionNames := getConfiguredIpSecConnection(extractLines(content))
	for _, connection := range connectionNames {
		ipsec.status[connection] = UNKNOWN
	}

	return ipsec, err
}

func (s IpSecStatus) QueryStatus() IpSecStatus {
	for connection := range s.status {
		out, _ := exec.Command("ipsec", "status", connection).Output()
		s.status[connection] = getStatus(out)
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
			return TUNNEL_INSTALLED
		} else {
			return CONNECTION_ESTABLISHED
		}
	} else if noMatchRegex.Match(statusLine) {
		return DOWN
	}

	return UNKNOWN
}

func loadConfig(fileName string) (string, error) {
	buf, err := ioutil.ReadFile(fileName)
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

func getConfiguredIpSecConnection(ipsecConfigLines []string) []string {
	connectionNames := []string{}

	for _, line := range ipsecConfigLines {
		re := regexp.MustCompile(`conn\s([a-zA-Z_-]+)`)
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
