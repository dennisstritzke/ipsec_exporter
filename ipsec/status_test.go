package ipsec

import (
	"errors"
	"testing"
)

type dummyStatusProvider struct {
	returnString string
	returnError  error
}

func (d *dummyStatusProvider) statusOutput(tunnel connection) (string, error) {
	if d.returnError != nil {
		return "", d.returnError
	}
	return d.returnString, nil
}

func TestQueryStatusSingle(t *testing.T) {
	tunnelName := "foo"
	configuration := &Configuration{
		tunnel: []connection{
			{name: tunnelName, ignored: false},
		},
	}

	status := queryStatus(configuration, &dummyStatusProvider{returnString: `Status of IKE charon daemon (strongSwan 5.3.5, Linux 4.4.0-31-generic, x86_64):
  uptime: 18 days, since Jan 24 16:00:17 2019
  malloc: sbrk 1486848, mmap 0, used 343952, free 1142896
  worker threads: 11 of 16 idle, 5/0/0/0 working, job queue: 0/0/0/0, scheduled: 4
  loaded plugins: charon test-vectors aes rc2 sha1 sha2 md4 md5 random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem openssl fips-prf gmp agent xcbc hmac gcm attr kernel-netlink resolve socket-default connmark stroke updown
Listening IP addresses:
  10.0.1.10
  10.0.0.10
Connections:
        foo:  10.0.0.10...137.37.37.37  IKEv2, dpddelay=30s
        foo:   local:  [117.17.17.17] uses pre-shared key authentication
        foo:   remote: [137.37.37.37] uses pre-shared key authentication
        foo:   child:  172.19.10.0/24 === 172.19.5.0/24 TUNNEL, dpdaction=restart
Security Associations (1 up, 0 connecting):
        foo[21]: ESTABLISHED 16 hours ago, 10.0.0.10[117.17.17.17]...137.37.37.37[137.37.37.37]
        foo[21]: IKEv2 SPIs: b26da4ae5279684d_i* 7f5b0cfd45d5dc94_r, pre-shared key reauthentication in 7 hours
        foo[21]: IKE proposal: AES_CBC_256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048
        foo{83}:  INSTALLED, TUNNEL, reqid 21, ESP in UDP SPIs: c96e6b17_i 34f71a54_o
        foo{83}:  AES_CBC_256/HMAC_SHA2_256_128, 2646320 bytes_i (37510 pkts, 0s ago), 3014849 bytes_o (54623 pkts, 0s ago), rekeying in 21 hours
        foo{83}:   172.19.10.0/24 === 172.19.5.0/24
`})
	tunnelInstanceId := "83"

	if len(status) != 1 {
		t.Errorf("Expected number of the tunnels")
		return
	}

	if len(status[tunnelName]) != 1 {
		t.Errorf("Expected number of the tunnel named '%s' instances", tunnelName)
		return
	}

	if _, ok := status[tunnelName][tunnelInstanceId]; !ok {
		t.Errorf("Expected instance id for the tunnel named '%s'", tunnelName)
	}

	if status[tunnelName][tunnelInstanceId] == nil {
		t.Errorf("Expected a status for the tunnel named '%s'.", tunnelName)
		return
	}

	if !status[tunnelName][tunnelInstanceId].up {
		t.Errorf("Expected tunnel '%s' to be reported up.", tunnelName)
	}

	actualStatus := status[tunnelName][tunnelInstanceId].status
	if actualStatus != tunnelInstalled {
		t.Errorf("Expected tunnel '%s' to have status '%d', but has '%d'.", tunnelName, tunnelInstalled, actualStatus)
	}

	expectedBytesIn := 2646320
	actualBytesIn := status[tunnelName][tunnelInstanceId].bytesIn
	if actualBytesIn != expectedBytesIn {
		t.Errorf("Expected '%d' received bytes, but was '%d'", expectedBytesIn, actualBytesIn)
	}

	expectedBytesOut := 3014849
	actualBytesOut := status[tunnelName][tunnelInstanceId].bytesOut
	if actualBytesOut != expectedBytesOut {
		t.Errorf("Expected '%d' sent bytes, but was '%d'", expectedBytesOut, actualBytesOut)
	}

	expectedPacketsIn := 37510
	actualPacketsIn := status[tunnelName][tunnelInstanceId].packetsIn
	if actualPacketsIn != expectedPacketsIn {
		t.Errorf("Expected '%d' received bytes, but was '%d'", expectedPacketsIn, actualPacketsIn)
	}

	expectedPacketsOut := 54623
	actualPacketsOut := status[tunnelName][tunnelInstanceId].packetsOut
	if actualPacketsOut != expectedPacketsOut {
		t.Errorf("Expected '%d' received bytes, but was '%d'", expectedPacketsOut, actualPacketsOut)
	}
}

func TestQueryStatusMulti(t *testing.T) {
	tunnelName := "conn-3"
	configuration := &Configuration{
		tunnel: []connection{
			{name: tunnelName, ignored: false},
		},
	}

	status := queryStatus(configuration, &dummyStatusProvider{returnString: `Status of IKE charon daemon (strongSwan 5.6.2, Linux 4.15.0-55-generic, x86_64):
  uptime: 23 minutes, since Feb 14 10:37:06 2021
  malloc: sbrk 2785280, mmap 0, used 818640, free 1966640
  worker threads: 11 of 16 idle, 5/0/0/0 working, job queue: 0/0/0/0, scheduled: 7
  loaded plugins: charon aesni aes rc2 sha2 sha1 md4 md5 mgf1 random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem openssl fips-prf gmp agent xcbc hmac gcm attr kernel-netlink resolve socket-default connmark stroke updown eap-mschapv2 xauth-generic counters
Listening IP addresses:
  10.0.0.1
Connections:
Security Associations (1 up, 0 connecting):
 conn[1]: ESTABLISHED 23 minutes ago, 10.0.0.1[117.17.17.17]...137.37.37.37[137.37.37.37]
 conn[1]: IKEv2 SPIs: b26da4ae5279684d_i* 7f5b0cfd45d5dc94_r, pre-shared key reauthentication in 5 hours
 conn[1]: IKE proposal: AES_CBC_256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048
conn-3{5}:  INSTALLED, TUNNEL, reqid 5, ESP in UDP SPIs: cfdf49cf_i a92c81e7_o
conn-3{5}:  AES_CBC_128/HMAC_SHA2_256_128, 52 bytes_i (1 pkt, 194s ago), 91 bytes_o (1 pkt, 12s ago), rekeying in 22 minutes
conn-3{5}:   10.1.0.0/24 10.2.0.0/24 10.3.0.0/24 === 10.28.0.0/17
conn-3{7}:  INSTALLED, TUNNEL, reqid 5, ESP in UDP SPIs: c49781fd_i dc53aa53_o
conn-3{7}:  AES_CBC_128/HMAC_SHA2_256_128, 100323100 bytes_i (92466 pkts, 1s ago), 15317385 bytes_o (61358 pkts, 1s ago), rekeying in 20 minutes
conn-3{7}:   10.1.0.0/24 10.2.0.0/24 10.3.0.0/24 === 10.28.0.0/17
conn-3{19}:  INSTALLED, TUNNEL, reqid 18, ESP in UDP SPIs: cf5475e1_i 9b9947af_o
conn-3{19}:  AES_CBC_128/HMAC_SHA2_256_128, 1362 bytes_i (10 pkts, 274s ago), 8722 bytes_o (11 pkts, 274s ago), rekeying in 38 minutes
conn-3{19}:   10.3.0.33/32 === 10.28.0.21/32
conn-3{20}:  INSTALLED, TUNNEL, reqid 19, ESP in UDP SPIs: c93fba2f_i f188e622_o
conn-3{20}:  AES_CBC_128/HMAC_SHA2_256_128, 1362 bytes_i (10 pkts, 62s ago), 8739 bytes_o (11 pkts, 62s ago), rekeying in 41 minutes
conn-3{20}:   10.3.0.40/32 === 10.28.0.21/32`})

	if len(status) != 1 {
		t.Errorf("Expected number of the tunnels")
		return
	}

	if len(status[tunnelName]) != 4 {
		t.Errorf("Expected number for the tunnel named '%s' instances was '4' but got '%d'", tunnelName, len(status[tunnelName]))
		return
	}

	for _, instanceId := range []string{"5", "7", "19", "20"} {
		if _, ok := status[tunnelName][instanceId]; !ok {
			t.Errorf("Expected connection %s{%s} statistics", tunnelName, instanceId)
		}

		if !status[tunnelName][instanceId].up {
			t.Errorf("Expected tunnel '%s' to be reported up.", tunnelName)
		}

		actualStatus := status[tunnelName][instanceId].status
		if actualStatus != tunnelInstalled {
			t.Errorf("Expected tunnel '%s' to have status '%d', but has '%d'.", tunnelName, tunnelInstalled, actualStatus)
		}
	}
}

func TestQueryStatus_ignoredTunnel(t *testing.T) {
	tunnelName := "foo"
	configuration := &Configuration{
		tunnel: []connection{
			{name: tunnelName, ignored: true},
		},
	}

	status := queryStatus(configuration, &dummyStatusProvider{returnString: ""})

	if len(status) != 1 {
		t.Errorf("Expected number of the tunnels")
		return
	}

	if _, ok := status[tunnelName][pseudoTunnelID]; !ok {
		t.Errorf("Expected instance id for the tunnel named '%s'", tunnelName)
	}

	if status[tunnelName][pseudoTunnelID] == nil {
		t.Errorf("Expected a status for the tunnel named '%s'.", tunnelName)
		return
	}

	if !status[tunnelName][pseudoTunnelID].up {
		t.Errorf("Expected tunnel '%s' to be reported up.", tunnelName)
	}

	actualStatus := status[tunnelName][pseudoTunnelID].status
	if actualStatus != ignored {
		t.Errorf("Expected tunnel '%s' to have status '%d', but has '%d'.", tunnelName, ignored, actualStatus)
	}
}

func TestQueryStatus_errorInProvider(t *testing.T) {
	tunnelName := "foo"
	configuration := &Configuration{
		tunnel: []connection{
			{name: tunnelName, ignored: false},
		},
	}

	status := queryStatus(configuration, &dummyStatusProvider{returnError: errors.New("doesn't matter")})

	if len(status) != 1 {
		t.Errorf("Expected number of tunnel named '%s' instances", tunnelName)
		return
	}

	if status[tunnelName][pseudoTunnelID] == nil {
		t.Errorf("Expected a status for the tunnel named '%s'.", tunnelName)
		return
	}

	if status[tunnelName][pseudoTunnelID].up {
		t.Errorf("Expected tunnel '%s' to be reported down.", tunnelName)
	}

	actualStatus := status[tunnelName][pseudoTunnelID].status
	if actualStatus != unknown {
		t.Errorf("Expected tunnel '%s' to have status '%d', but has '%d'.", tunnelName, unknown, actualStatus)
	}
}

func TestStatus_noMatch(t *testing.T) {
	var (
		input = "Security Associations (1 up, 0 connecting):\n	 no match"
		conn  = connection{name: "fancy"}
	)

	status := extractStatus([]byte(input), conn, pseudoTunnelID)

	if status != down {
		t.Errorf("Expected tunnel to be 'down', but was state %d", status)
	}
}

func TestStatus_connectionUpTunnelMissing(t *testing.T) {
	var (
		input = "Security Associations (1 up, 0 connecting):\n  fancy[3]: ESTABLISHED 16 hours ago, 10.0.0.7[213.123.123.9]...212.93.93.93[212.93.93.93]\n	 fancy{134}:  REKEYED, TUNNEL, reqid 2, ESP in UDP SPIs: cc2e965d_i 6d01c0d7_o\n 	fancy{134}:   10.2.0.112/29 === 10.3.0.0/24"

		conn   = connection{name: "fancy"}
		connId = "134"
	)

	status := extractStatus([]byte(input), conn, connId)

	if status != connectionEstablished {
		t.Errorf("Expected tunnel to be 'connectionEstablished', but was state %d", status)
	}
}

func TestStatus_operational(t *testing.T) {
	var (
		input = "Security Associations (1 up, 0 connecting):\n  fancy[3]: ESTABLISHED 16 hours ago, 10.0.0.7[213.123.123.9]...212.93.93.93[212.93.93.93]\n	 fancy{134}:  INSTALLED, TUNNEL, reqid 2, ESP in UDP SPIs: cc2e965d_i 6d01c0d7_o\n 	fancy{134}:   10.2.0.112/29 === 10.3.0.0/24"

		conn   = connection{name: "fancy"}
		connId = "134"
	)

	status := extractStatus([]byte(input), conn, connId)

	if status != tunnelInstalled {
		t.Errorf("Expected tunnel to be 'tunnelInstalled', but was state %d", status)
	}
}

func TestTunnelStatisticsFull(t *testing.T) {
	tunnelName := "foo"
	configuration := &Configuration{
		tunnel: []connection{
			{name: tunnelName, ignored: false},
		},
	}

	status := queryStatus(configuration, &dummyStatusProvider{returnString: `Status of IKE charon daemon (strongSwan 5.3.5, Linux 4.4.0-31-generic, x86_64):
  uptime: 18 days, since Jan 24 16:00:17 2019
  malloc: sbrk 1486848, mmap 0, used 343952, free 1142896
  worker threads: 11 of 16 idle, 5/0/0/0 working, job queue: 0/0/0/0, scheduled: 4
  loaded plugins: charon test-vectors aes rc2 sha1 sha2 md4 md5 random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem openssl fips-prf gmp agent xcbc hmac gcm attr kernel-netlink resolve socket-default connmark stroke updown
Listening IP addresses:
  10.0.1.10
  10.0.0.10
Connections:
        foo:  10.0.0.10...137.37.37.37  IKEv2, dpddelay=30s
        foo:   local:  [117.17.17.17] uses pre-shared key authentication
        foo:   remote: [137.37.37.37] uses pre-shared key authentication
        foo:   child:  172.19.10.0/24 === 172.19.5.0/24 TUNNEL, dpdaction=restart
Security Associations (1 up, 0 connecting):
        foo[21]: ESTABLISHED 16 hours ago, 10.0.0.10[117.17.17.17]...137.37.37.37[137.37.37.37]
        foo[21]: IKEv2 SPIs: b26da4ae5279684d_i* 7f5b0cfd45d5dc94_r, pre-shared key reauthentication in 7 hours
        foo[21]: IKE proposal: AES_CBC_256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048
        foo{83}:  INSTALLED, TUNNEL, reqid 21, ESP in UDP SPIs: c96e6b17_i 34f71a54_o
        foo{83}:  AES_CBC_256/HMAC_SHA2_256_128, 2646320 bytes_i (37510 pkts, 0s ago), 3014849 bytes_o (54623 pkts, 0s ago), rekeying in 21 hours
        foo{83}:   172.19.10.0/24 === 172.19.5.0/24
`})
	tunnelInstanceId := "83"

	if status[tunnelName][tunnelInstanceId].bytesIn != 2646320 {
		t.Errorf("Expected to match '2646320' but got '%d'", status[tunnelName][tunnelInstanceId].bytesIn)
		return
	}

	if status[tunnelName][tunnelInstanceId].packetsIn != 37510 {
		t.Errorf("Expected to match '37510' but got '%d'", status[tunnelName][tunnelInstanceId].packetsIn)
		return
	}

	if status[tunnelName][tunnelInstanceId].bytesOut != 3014849 {
		t.Errorf("Expected to match '3014849' but got '%d'", status[tunnelName][tunnelInstanceId].bytesOut)
		return
	}

	if status[tunnelName][tunnelInstanceId].packetsOut != 54623 {
		t.Errorf("Expected to match '54623' but got '%d'", status[tunnelName][tunnelInstanceId].packetsOut)
		return
	}
}

func TestTunnelStatisticsWithoutPacketsIn(t *testing.T) {
	tunnelName := "foo"
	configuration := &Configuration{
		tunnel: []connection{
			{name: tunnelName, ignored: false},
		},
	}

	status := queryStatus(configuration, &dummyStatusProvider{returnString: `Status of IKE charon daemon (strongSwan 5.3.5, Linux 4.4.0-31-generic, x86_64):
  uptime: 18 days, since Jan 24 16:00:17 2019
  malloc: sbrk 1486848, mmap 0, used 343952, free 1142896
  worker threads: 11 of 16 idle, 5/0/0/0 working, job queue: 0/0/0/0, scheduled: 4
  loaded plugins: charon test-vectors aes rc2 sha1 sha2 md4 md5 random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem openssl fips-prf gmp agent xcbc hmac gcm attr kernel-netlink resolve socket-default connmark stroke updown
Listening IP addresses:
  10.0.1.10
  10.0.0.10
Connections:
        foo:  10.0.0.10...137.37.37.37  IKEv2, dpddelay=30s
        foo:   local:  [117.17.17.17] uses pre-shared key authentication
        foo:   remote: [137.37.37.37] uses pre-shared key authentication
        foo:   child:  172.19.10.0/24 === 172.19.5.0/24 TUNNEL, dpdaction=restart
Security Associations (1 up, 0 connecting):
        foo[21]: ESTABLISHED 16 hours ago, 10.0.0.10[117.17.17.17]...137.37.37.37[137.37.37.37]
        foo[21]: IKEv2 SPIs: b26da4ae5279684d_i* 7f5b0cfd45d5dc94_r, pre-shared key reauthentication in 7 hours
        foo[21]: IKE proposal: AES_CBC_256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048
        foo{83}:  INSTALLED, TUNNEL, reqid 21, ESP in UDP SPIs: c96e6b17_i 34f71a54_o
        foo{83}:  AES_CBC_256/HMAC_SHA2_256_128, 0 bytes_i, 3014849 bytes_o (54623 pkts, 0s ago), rekeying in 21 hours
        foo{83}:   172.19.10.0/24 === 172.19.5.0/24
`})
	tunnelInstanceId := "83"

	if status[tunnelName][tunnelInstanceId].bytesIn != 0 {
		t.Errorf("Expected to match '0' but got '%d'", status[tunnelName][tunnelInstanceId].bytesIn)
		return
	}

	if status[tunnelName][tunnelInstanceId].packetsIn != 0 {
		t.Errorf("Expected to match '0' but got '%d'", status[tunnelName][tunnelInstanceId].packetsIn)
		return
	}

	if status[tunnelName][tunnelInstanceId].bytesOut != 3014849 {
		t.Errorf("Expected to match '3014849' but got '%d'", status[tunnelName][tunnelInstanceId].bytesOut)
		return
	}

	if status[tunnelName][tunnelInstanceId].packetsOut != 54623 {
		t.Errorf("Expected to match '54623' but got '%d'", status[tunnelName][tunnelInstanceId].packetsOut)
		return
	}
}

func TestTunnelStatisticsWithoutPacketsInOut(t *testing.T) {
	tunnelName := "foo"
	configuration := &Configuration{
		tunnel: []connection{
			{name: tunnelName, ignored: false},
		},
	}

	status := queryStatus(configuration, &dummyStatusProvider{returnString: `Status of IKE charon daemon (strongSwan 5.3.5, Linux 4.4.0-31-generic, x86_64):
  uptime: 18 days, since Jan 24 16:00:17 2019
  malloc: sbrk 1486848, mmap 0, used 343952, free 1142896
  worker threads: 11 of 16 idle, 5/0/0/0 working, job queue: 0/0/0/0, scheduled: 4
  loaded plugins: charon test-vectors aes rc2 sha1 sha2 md4 md5 random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem openssl fips-prf gmp agent xcbc hmac gcm attr kernel-netlink resolve socket-default connmark stroke updown
Listening IP addresses:
  10.0.1.10
  10.0.0.10
Connections:
        foo:  10.0.0.10...137.37.37.37  IKEv2, dpddelay=30s
        foo:   local:  [117.17.17.17] uses pre-shared key authentication
        foo:   remote: [137.37.37.37] uses pre-shared key authentication
        foo:   child:  172.19.10.0/24 === 172.19.5.0/24 TUNNEL, dpdaction=restart
Security Associations (1 up, 0 connecting):
        foo[21]: ESTABLISHED 16 hours ago, 10.0.0.10[117.17.17.17]...137.37.37.37[137.37.37.37]
        foo[21]: IKEv2 SPIs: b26da4ae5279684d_i* 7f5b0cfd45d5dc94_r, pre-shared key reauthentication in 7 hours
        foo[21]: IKE proposal: AES_CBC_256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048
        foo{83}:  INSTALLED, TUNNEL, reqid 21, ESP in UDP SPIs: c96e6b17_i 34f71a54_o
        foo{83}:  AES_CBC_256/HMAC_SHA2_256_128, 0 bytes_i, 0 bytes_o, rekeying in 21 hours
        foo{83}:   172.19.10.0/24 === 172.19.5.0/24
`})
	tunnelInstanceId := "83"

	if status[tunnelName][tunnelInstanceId].bytesIn != 0 {
		t.Errorf("Expected to match '0' but got '%d'", status[tunnelName][tunnelInstanceId].bytesIn)
		return
	}

	if status[tunnelName][tunnelInstanceId].packetsIn != 0 {
		t.Errorf("Expected to match '0' but got '%d'", status[tunnelName][tunnelInstanceId].packetsIn)
		return
	}

	if status[tunnelName][tunnelInstanceId].bytesOut != 0 {
		t.Errorf("Expected to match '0' but got '%d'", status[tunnelName][tunnelInstanceId].bytesOut)
		return
	}

	if status[tunnelName][tunnelInstanceId].packetsOut != 0 {
		t.Errorf("Expected to match '0' but got '%d'", status[tunnelName][tunnelInstanceId].packetsOut)
		return
	}
}
