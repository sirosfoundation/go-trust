package emrtd

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	crlCountDesc = prometheus.NewDesc("go_trust_emrtd_crl_count",
		"Number of loaded CRLs per issuing state", []string{"country"}, nil)
	crlAgeDesc = prometheus.NewDesc("go_trust_emrtd_crl_age_seconds",
		"Seconds since thisUpdate of the newest loaded CRL per issuing state", []string{"country"}, nil)
	crlNextUpdateDesc = prometheus.NewDesc("go_trust_emrtd_crl_next_update_timestamp_seconds",
		"Unix time of the latest nextUpdate among the loaded CRLs per issuing state (0 if none sets one)", []string{"country"}, nil)
)

// crlCollector exports CRL freshness per country, so operators can tell a
// stalled CRL feed (growing age, nextUpdate in the past) from a revocation.
// States without any loaded CRL have no series.
type crlCollector struct{ r *Registry }

// Collector returns a Prometheus collector for this registry's CRL freshness:
// go_trust_emrtd_crl_count, go_trust_emrtd_crl_age_seconds and
// go_trust_emrtd_crl_next_update_timestamp_seconds, each labelled by country.
func (r *Registry) Collector() prometheus.Collector { return crlCollector{r: r} }

func (c crlCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- crlCountDesc
	ch <- crlAgeDesc
	ch <- crlNextUpdateDesc
}

func (c crlCollector) Collect(ch chan<- prometheus.Metric) {
	snap := c.r.snap.Load()
	if snap == nil {
		return
	}
	now := c.r.cfg.Now()
	for country, crls := range snap.crls {
		if len(crls) == 0 {
			continue
		}
		var newest, nextUpdate time.Time
		for _, crl := range crls {
			if crl.ThisUpdate.After(newest) {
				newest = crl.ThisUpdate
			}
			if crl.NextUpdate.After(nextUpdate) {
				nextUpdate = crl.NextUpdate
			}
		}
		next := 0.0
		if !nextUpdate.IsZero() {
			next = float64(nextUpdate.Unix())
		}
		ch <- prometheus.MustNewConstMetric(crlCountDesc, prometheus.GaugeValue, float64(len(crls)), country)
		ch <- prometheus.MustNewConstMetric(crlAgeDesc, prometheus.GaugeValue, now.Sub(newest).Seconds(), country)
		ch <- prometheus.MustNewConstMetric(crlNextUpdateDesc, prometheus.GaugeValue, next, country)
	}
}
