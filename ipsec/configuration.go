package ipsec

import (
	"io/ioutil"
	"regexp"
	"strings"
)

type connection struct {
	name    string
	ignored bool
}

type Configuration struct {
	tunnel []connection
}

func (c *Configuration) HasTunnels() bool {
	return len(c.tunnel) != 0
}

// NewConfiguration creates a Configuration struct out of an IPsec configuration from the filesystem.
func NewConfiguration(fileName string) (*Configuration, error) {
	return newIpSecConfigLoader(fileName).Load()
}

type ipSecConfigurationLoader struct {
	FileName string
}

func newIpSecConfigLoader(fileName string) *ipSecConfigurationLoader {
	return &ipSecConfigurationLoader{
		FileName: fileName,
	}
}

func (l *ipSecConfigurationLoader) Load() (*Configuration, error) {
	content, err := l.loadConfig()
	connectionNames := l.getConfiguredIpSecConnection(content)

	return &Configuration{
		tunnel: connectionNames,
	}, err
}

func (l *ipSecConfigurationLoader) getConfiguredIpSecConnection(ipSecConfigContent string) []connection {
	var connections []connection

	ipSecConfigLines := l.extractLines(ipSecConfigContent)
	for _, line := range ipSecConfigLines {
		// Match connection definition lines
		re := regexp.MustCompile(`conn\s([a-zA-Z0-9_-]+)`)
		match := re.FindStringSubmatch(line)
		if len(match) >= 2 {
			connections = append(connections, connection{name: match[1], ignored: false})
		}

		// Match auto=ignore lines
		reAutoIgnore := regexp.MustCompile(`auto=ignore`)
		matchAutoIgnore := reAutoIgnore.FindStringSubmatch(line)
		if len(matchAutoIgnore) >= 1 {
			connectionIndex := len(connections) - 1
			if len(connections) > connectionIndex {
				connections[connectionIndex].ignored = true
			}
		}
	}

	return connections
}

func (l *ipSecConfigurationLoader) loadConfig() (string, error) {
	buf, err := ioutil.ReadFile(l.FileName)
	if err != nil {
		return "", err
	}
	s := string(buf)
	return s, nil
}

func (l *ipSecConfigurationLoader) extractLines(ipsecConfig string) []string {
	return strings.Split(ipsecConfig, "\n")
}
