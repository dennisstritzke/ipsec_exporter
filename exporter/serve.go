package exporter

import (
	"net/http"
	"os"

	"github.com/dennisstritzke/ipsec_exporter/ipsec"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
)

var IpSecConfigFile string
var WebListenAddress string

var ipSecConfiguration *ipsec.Configuration

var logger = promlog.New(&promlog.Config{})

func Serve() {
	var err error
	ipSecConfiguration, err = ipsec.NewConfiguration(IpSecConfigFile)
	if err != nil {
		level.Error(logger).Log("err", err)
		os.Exit(1)
		return
	}
	if !ipSecConfiguration.HasTunnels() {
		level.Warn(logger).Log("msg", "Found no configured connections in "+IpSecConfigFile)
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

	level.Info(logger).Log("msg", "Listening on: "+WebListenAddress)
	err = http.ListenAndServe(WebListenAddress, nil)
	if err != nil {
		level.Error(logger).Log("err", err)
		os.Exit(1)
	}
}
