package ipsecexporter

import (
	"net/http"
	"strconv"
	"github.com/prometheus/common/log"
)

var IpsecConfigFile string
var WebListenAddress int

var ipsecConfiguration IpSecConfiguration

func Serve() {
	var err error
	ipsecConfiguration, err = FetchIpSecConfiguration(IpsecConfigFile)
	if err != nil {
		log.Fatal(err)
		return
	}
	if len(ipsecConfiguration.tunnel) == 0 {
		log.Warn("Found no configured connections in " + IpsecConfigFile)
	}

	http.HandleFunc("/", redirectToMetrics)
	http.HandleFunc("/metrics", prometheusMetrics)

	log.Infoln("Listening on", WebListenAddress)
	err = http.ListenAndServe(":" + strconv.Itoa(WebListenAddress), nil)
	if err != nil {
		log.Fatal(err)
	}
}

func redirectToMetrics(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/metrics", http.StatusMovedPermanently)
}

func prometheusMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Write([]byte(ipsecConfiguration.QueryStatus().PrometheusMetrics()))
}
