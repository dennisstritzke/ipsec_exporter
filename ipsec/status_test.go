package ipsec

import "testing"

func TestStatus_noMatch(t *testing.T) {
	input := "Security Associations (1 up, 0 connecting):\n	 no match"
	status := extractStatus([]byte(input))

	if status != down {
		t.Errorf("Expected tunnel to be 'down', but was state %d", status)
	}
}

func TestStatus_connectionUpTunnelMissing(t *testing.T) {
	input := "Security Associations (1 up, 0 connecting):\n  fancy[3]: ESTABLISHED 16 hours ago, 10.0.0.7[213.123.123.9]...212.93.93.93[212.93.93.93]\n	 fancy{134}:  REKEYED, TUNNEL, reqid 2, ESP in UDP SPIs: cc2e965d_i 6d01c0d7_o\n 	fancy{134}:   10.2.0.112/29 === 10.3.0.0/24"
	status := extractStatus([]byte(input))

	if status != connectionEstablished {
		t.Errorf("Expected tunnel to be 'connectionEstablished', but was state %d", status)
	}
}

func TestStatus_operational(t *testing.T) {
	input := "Security Associations (1 up, 0 connecting):\n  fancy[3]: ESTABLISHED 16 hours ago, 10.0.0.7[213.123.123.9]...212.93.93.93[212.93.93.93]\n	 fancy{134}:  INSTALLED, TUNNEL, reqid 2, ESP in UDP SPIs: cc2e965d_i 6d01c0d7_o\n 	fancy{134}:   10.2.0.112/29 === 10.3.0.0/24"
	status := extractStatus([]byte(input))

	if status != tunnelInstalled {
		t.Errorf("Expected tunnel to be 'tunnelInstalled', but was state %d", status)
	}
}
