package ipsec

import (
	"testing"
)

func dummyIpSecConfigLoader() *ipSecConfigurationLoader {
	return newIpSecConfigLoader("dummy.conf")
}

func TestGetConfiguredIpSecConnections_simpleLine(t *testing.T) {
	input := "conn fancy_dc"
	connections, _ := dummyIpSecConfigLoader().getConfiguredIpSecConnection(input)

	if len(connections) != 1 {
		t.Errorf("Expected to have found 1 connection, but has found %d", len(connections))
		return
	}

	if connections[0].name != "fancy_dc" {
		t.Errorf("Should have found connection 'fancy_dc', but found %s", connections[0].name)
	}
}

func TestGetConfiguredIpSecConnections_connectionIncludingDots(t *testing.T) {
	input := "conn fancy.dc"
	connections, _ := dummyIpSecConfigLoader().getConfiguredIpSecConnection(input)

	if len(connections) != 1 {
		t.Errorf("Expected to have found 1 connection, but has found %d", len(connections))
		return
	}

	if connections[0].name != "fancy.dc" {
		t.Errorf("Should have found connection 'fancy.dc', but found %s", connections[0].name)
	}
}

func TestGetConfiguredIpSecConnections_connectionIncludingNumber(t *testing.T) {
	input := "conn fancy_345"
	connections, _ := dummyIpSecConfigLoader().getConfiguredIpSecConnection(input)

	if len(connections) != 1 {
		t.Errorf("Expected to have found 1 connection, but has found %d", len(connections))
		return
	}

	if connections[0].name != "fancy_345" {
		t.Errorf("Should have found connection 'fancy_345', but found %s", connections[0].name)
	}
}

func TestGetConfiguredIpSecConnections_simpleLineAndComment(t *testing.T) {
	input := "conn fancy_dc # very wise comment"
	connections, _ := dummyIpSecConfigLoader().getConfiguredIpSecConnection(input)

	if len(connections) != 1 {
		t.Errorf("Expected to have found 1 connection, but has found %d", len(connections))
		return
	}

	if connections[0].name != "fancy_dc" {
		t.Errorf("Should have found connection 'fancy_dc', but found %s", connections[0].name)
	}
}

func TestGetConfiguredIpSecConnections_withDefault(t *testing.T) {
	input := "conn %default\n  esp=aes256-sha1\n\nconn fancy_dc"
	connections, _ := dummyIpSecConfigLoader().getConfiguredIpSecConnection(input)

	if len(connections) != 1 {
		t.Errorf("Expected to have found 1 connection, but has found %d", len(connections))
		return
	}

	if connections[0].name != "fancy_dc" {
		t.Errorf("Should have found connection 'fancy_dc', but found %s", connections[0].name)
	}
}

func TestGetConfiguredIpSecConnections_withNewLines(t *testing.T) {
	input := "conn fancy_dc\n  esp=aes256-sha256-modp2048!\n\n  left=10.0.0.7\n\nconn second_dc"
	connections, _ := dummyIpSecConfigLoader().getConfiguredIpSecConnection(input)

	if len(connections) != 2 {
		t.Errorf("Expected to have found 2 connection, but has found %d", len(connections))
		return
	}

	if connections[0].name != "fancy_dc" {
		t.Errorf("Should have found connection 'fancy_dc', but found %s", connections[0].name)
	}

	if connections[1].name != "second_dc" {
		t.Errorf("Should have found connection 'second_dc', but found %s", connections[1].name)
	}
}

func TestGetConfiguredIpSecConnections_autoIgnore(t *testing.T) {
	input := "conn fancy_dc\n  auto=ignore"
	connections, _ := dummyIpSecConfigLoader().getConfiguredIpSecConnection(input)

	if len(connections) != 1 {
		t.Errorf("Expected to have found 1 connection, but has found %d", len(connections))
		return
	}

	if connections[0].name != "fancy_dc" {
		t.Errorf("Should have found connection 'fancy_dc', but found %s", connections[0].name)
	}

	if !connections[0].ignored {
		t.Errorf("Expected connection to be ignored")
	}
}

func TestGetConfiguredIpSecConnections_autoIgnoreMultipleTunnels(t *testing.T) {
	input := "conn fancy_dc\n  esp=aes256-sha256-modp2048!\n\n  left=10.0.0.7\n\nconn second_dc\n  auto=ignore"
	connections, _ := dummyIpSecConfigLoader().getConfiguredIpSecConnection(input)

	if len(connections) != 2 {
		t.Errorf("Expected to have found 2 connection, but has found %d", len(connections))
		return
	}

	if connections[0].ignored {
		t.Errorf("Expected connection '%s' not to be ignored", connections[0].name)
	}

	if !connections[1].ignored {
		t.Errorf("Expected connection '%s' to be ignored", connections[1].name)
	}
}

func TestGetConfiguredIpSecConnections_returnsIncludeFileName(t *testing.T) {
	includePatternString := "/etc/not/default/*.conf"
	input := "include " + includePatternString
	connections, includeFiles := dummyIpSecConfigLoader().getConfiguredIpSecConnection(input)

	if len(connections) != 0 {
		t.Errorf("Expected to have found 0 connection, but has found %d", len(connections))
		return
	}

	if len(includeFiles) != 1 {
		t.Errorf("Expected to have found 1 included file, but has found %d", len(includeFiles))
		return
	}

	if includeFiles[0] != includePatternString {
		t.Errorf("Expected included file to be '%s', but was '%s'", includePatternString, includeFiles[0])
	}
}

func TestExtractLines(t *testing.T) {
	input := "First\nSecond\n\nThird"
	inputSliced := dummyIpSecConfigLoader().extractLines(input)

	if len(inputSliced) != 4 {
		t.Errorf("Expected output to have 4 items, but has %d", len(inputSliced))
		return
	}

	checkInput(t, inputSliced, 0, "First")
	checkInput(t, inputSliced, 1, "Second")
	checkInput(t, inputSliced, 2, "")
	checkInput(t, inputSliced, 3, "Third")
}

func TestIgnoreComments(t *testing.T) {
	input := "First\n# Second\n\n#Third\nFourth\n# \nFifth"
	inputSliced := dummyIpSecConfigLoader().extractLines(input)

	if len(inputSliced) != 4 {
		t.Errorf("Expected output to have 4 items, but has %d", len(inputSliced))
	}

	checkInput(t, inputSliced, 0, "First")
	checkInput(t, inputSliced, 1, "")
	checkInput(t, inputSliced, 2, "Fourth")
	checkInput(t, inputSliced, 3, "Fifth")
}

func checkInput(t *testing.T, sliced []string, index int, expected string) {
	if sliced[index] != expected {
		t.Errorf("Expected inputSliced[%d] to be %s but was %s", index, expected, sliced[index])
	}
}
