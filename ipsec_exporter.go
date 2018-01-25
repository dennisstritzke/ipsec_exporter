package main

import (
	"net/http"
	"ipsec-exporter/ipsec"
)

func main() {
	http.HandleFunc("/", redirectToMetrics)
	http.HandleFunc("/metrics", prometheusMetrics)
	http.ListenAndServe(":9101", nil)
}

func redirectToMetrics(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/metrics", http.StatusMovedPermanently)
}

func prometheusMetrics(w http.ResponseWriter, _ *http.Request) {
	ipsecStatus, _ := ipsec.CreateIpSecStatus("/etc/ipsec.conf")
	w.Write([]byte(ipsecStatus.QueryStatus().PrometheusMetrics()))
}