package exporter

import (
	"github.com/dennisstritzke/ipsec_exporter/ipsec"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
	"net/http"
	"strconv"
)

var IpSecConfigFile string
var WebListenAddress int

var ipSecConfiguration *ipsec.Configuration

func Serve() {
	var err error
	ipSecConfiguration, err = ipsec.NewConfiguration(IpSecConfigFile)
	if err != nil {
		log.Fatal(err)
		return
	}
	if !ipSecConfiguration.HasTunnels() {
		log.Warn("Found no configured connections in " + IpSecConfigFile)
	}

	collector := ipsec.NewCollector(ipSecConfiguration)
	prometheus.MustRegister(collector)

	http.HandleFunc("/", redirectToMetrics)
	http.Handle("/metrics", promhttp.Handler())

	log.Infoln("Listening on", WebListenAddress)
	err = http.ListenAndServe(":"+strconv.Itoa(WebListenAddress), nil)
	if err != nil {
		log.Fatal(err)
	}
}

func redirectToMetrics(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/metrics", http.StatusMovedPermanently)
}
