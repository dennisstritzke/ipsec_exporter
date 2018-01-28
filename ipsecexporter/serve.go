package ipsecexporter

import (
	"net/http"
	"strconv"
	"github.com/prometheus/common/log"
)

var IpsecConfigFile string
var WebListenAddress int

func Serve() {
	http.HandleFunc("/", redirectToMetrics)
	http.HandleFunc("/metrics", prometheusMetrics)

	log.Infoln("Listening on", WebListenAddress)
	err := http.ListenAndServe(":" + strconv.Itoa(WebListenAddress), nil)
	if err != nil {
		log.Fatal(err)
	}
}

func redirectToMetrics(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/metrics", http.StatusMovedPermanently)
}

func prometheusMetrics(w http.ResponseWriter, _ *http.Request) {
	ipsecStatus, _ := CreateIpSecStatus(IpsecConfigFile)
	w.Write([]byte(ipsecStatus.QueryStatus().PrometheusMetrics()))
}
