package ipsec

import (
	"testing"
)

func TestGetConfiguredIpSecConnections_simpleLine(t *testing.T) {
	input := []string{"conn fancy_dc"}
	connections := getConfiguredIpSecConnection(input)

	if len(connections) != 1 {
		t.Errorf("Expected to have found 1 connection, but has found %d", len(connections))
		return
	}

	if connections[0] != "fancy_dc" {
		t.Errorf("Should have found connection 'fancy_dc', but found %s", connections[0])
	}
}

func TestGetConfiguredIpSecConnections_simpleLineAndComment(t *testing.T) {
	input := []string{"conn fancy_dc # very wise comment"}
	connections := getConfiguredIpSecConnection(input)

	if len(connections) != 1 {
		t.Errorf("Expected to have found 1 connection, but has found %d", len(connections))
		return
	}

	if connections[0] != "fancy_dc" {
		t.Errorf("Should have found connection 'fancy_dc', but found %s", connections[0])
	}
}

func TestGetConfiguredIpSecConnections_withDefault(t *testing.T) {
	input := []string{"conn %default", "  esp=aes256-sha1", "", "conn fancy_dc"}
	connections := getConfiguredIpSecConnection(input)

	if len(connections) != 1 {
		t.Errorf("Expected to have found 1 connection, but has found %d", len(connections))
		return
	}

	if connections[0] != "fancy_dc" {
		t.Errorf("Should have found connection 'fancy_dc', but found %s", connections[0])
	}
}

func TestGetConfiguredIpSecConnections_withNewLines(t *testing.T) {
	input := []string{"conn fancy_dc", "  esp=aes256-sha256-modp2048!", "", "  left=10.0.0.7", "", "conn second_dc"}
	connections := getConfiguredIpSecConnection(input)

	if len(connections) != 2 {
		t.Errorf("Expected to have found 2 connection, but has found %d", len(connections))
		return
	}

	if connections[0] != "fancy_dc" {
		t.Errorf("Should have found connection 'fancy_dc', but found %s", connections[0])
	}

	if connections[1] != "second_dc" {
		t.Errorf("Should have found connection 'second_dc', but found %s", connections[1])
	}
}

func TestExtractLines(t *testing.T) {
	input := "First\nSecond\n\nThird"
	inputSliced := extractLines(input)

	if len(inputSliced) != 4 {
		t.Errorf("Expected output to have 4 items, but has %d", len(inputSliced))
		return
	}

	checkInput(t, inputSliced, 0, "First")
	checkInput(t, inputSliced, 1, "Second")
	checkInput(t, inputSliced, 2, "")
	checkInput(t, inputSliced, 3, "Third")
}

func checkInput(t *testing.T, sliced []string, index int, expected string) {
	if sliced[index] != expected {
		t.Errorf("Expected inputSliced[%s] to be %s but was %s", index, expected, sliced[index])
	}
}

func TestStatus_noMatch(t *testing.T) {
	input := "Security Associations (1 up, 0 connecting):\n	 no match"
	status := getStatus([]byte(input))

	if status != DOWN {
		t.Errorf("Expected tunnel to be DOWN, but was state %d", status)
	}
}

func TestStatus_connectionUpTunnelMissing(t *testing.T) {
	input := "Security Associations (1 up, 0 connecting):\n  fancy[3]: ESTABLISHED 16 hours ago, 10.0.0.7[213.123.123.9]...212.93.93.93[212.93.93.93]\n	 fancy{134}:  REKEYED, TUNNEL, reqid 2, ESP in UDP SPIs: cc2e965d_i 6d01c0d7_o\n 	fancy{134}:   10.2.0.112/29 === 10.3.0.0/24"
	status := getStatus([]byte(input))

	if status != CONNECTION_ESTABLISHED {
		t.Errorf("Expected tunnel to be CONNECTION_ESTABLISHED, but was state %d", status)
	}
}

func TestStatus_operational(t *testing.T) {
	input := "Security Associations (1 up, 0 connecting):\n  fancy[3]: ESTABLISHED 16 hours ago, 10.0.0.7[213.123.123.9]...212.93.93.93[212.93.93.93]\n	 fancy{134}:  INSTALLED, TUNNEL, reqid 2, ESP in UDP SPIs: cc2e965d_i 6d01c0d7_o\n 	fancy{134}:   10.2.0.112/29 === 10.3.0.0/24"
	status := getStatus([]byte(input))

	if status != TUNNEL_INSTALLED {
		t.Errorf("Expected tunnel to be TUNNEL_INSTALLED, but was state %d", status)
	}
}
