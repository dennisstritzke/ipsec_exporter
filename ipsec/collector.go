package ipsec

import "github.com/prometheus/client_golang/prometheus"

var (
	tunnelDesc = prometheus.NewDesc("ipsec_status", "ipsec status values", []string{"tunnel"}, nil)
)

func NewCollector(configurations ... *Configuration) *Collector {
	return &Collector{
		configurations: configurations,
	}
}

type Collector struct {
	configurations []*Configuration
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- tunnelDesc
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	for _, configuration := range c.configurations {
		status := queryStatus(configuration)

		for tunnel, tunnelStatus := range status.status {
			ch <- prometheus.MustNewConstMetric(tunnelDesc, prometheus.GaugeValue, float64(tunnelStatus), tunnel)
		}
	}
}
