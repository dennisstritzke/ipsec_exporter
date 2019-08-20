package exporter

import (
	"github.com/dennisstritzke/ipsec_exporter/ipsec"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
	"net/http"
)

var IpSecConfigFile string
var WebListenAddress string

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

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html>
             <head><title>IPsec Exporter</title></head>
             <body>
             <h1>IPsec Exporter</h1>
             <p><a href='/metrics'>Metrics</a></p>
             </body>
             </html>`))
	})
	http.Handle("/metrics", promhttp.Handler())

	log.Infoln("Listening on", WebListenAddress)
	err = http.ListenAndServe(WebListenAddress, nil)
	if err != nil {
		log.Fatal(err)
	}
}
