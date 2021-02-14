package ipsec

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	variableLabels = []string{"tunnel", "tunnel_instance"}

	metricUp         = prometheus.NewDesc("ipsec_up", "value indicating a successful scrape", variableLabels, nil)
	metricStatus     = prometheus.NewDesc("ipsec_status", "ipsec status value", variableLabels, nil)
	metricBytesIn    = prometheus.NewDesc("ipsec_in_bytes", "received bytes per tunnel", variableLabels, nil)
	metricBytesOut   = prometheus.NewDesc("ipsec_out_bytes", "sent bytes per tunnel", variableLabels, nil)
	metricPacketsIn  = prometheus.NewDesc("ipsec_in_packets", "received packets per tunnel", variableLabels, nil)
	metricPacketsOut = prometheus.NewDesc("ipsec_out_packets", "sent packets per tunnel", variableLabels, nil)
)

func NewCollector(configurations ...*Configuration) *Collector {
	return &Collector{
		configurations: configurations,
	}
}

type Collector struct {
	configurations []*Configuration
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- metricUp
	ch <- metricStatus
	ch <- metricBytesIn
	ch <- metricBytesOut
	ch <- metricPacketsIn
	ch <- metricPacketsOut
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	for _, configuration := range c.configurations {
		tunnelStatuses := queryStatus(configuration, &cliStatusProvider{})

		for tunnel, tunnelInstanceStatuses := range tunnelStatuses {
			for tunnelInstance, tunnelStatus := range tunnelInstanceStatuses {
				ch <- prometheus.MustNewConstMetric(metricUp, prometheus.GaugeValue, c.toFloat64(tunnelStatus.up), tunnel, tunnelInstance)
				ch <- prometheus.MustNewConstMetric(metricStatus, prometheus.GaugeValue, float64(tunnelStatus.status), tunnel, tunnelInstance)
				ch <- prometheus.MustNewConstMetric(metricBytesIn, prometheus.CounterValue, float64(tunnelStatus.bytesIn), tunnel, tunnelInstance)
				ch <- prometheus.MustNewConstMetric(metricBytesOut, prometheus.CounterValue, float64(tunnelStatus.bytesOut), tunnel, tunnelInstance)
				ch <- prometheus.MustNewConstMetric(metricPacketsIn, prometheus.CounterValue, float64(tunnelStatus.packetsIn), tunnel, tunnelInstance)
				ch <- prometheus.MustNewConstMetric(metricPacketsOut, prometheus.CounterValue, float64(tunnelStatus.packetsOut), tunnel, tunnelInstance)
			}
		}
	}
}

func (c *Collector) toFloat64(value bool) float64 {
	if value {
		return 1
	}

	return 0
}
