package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const namespace = "crowdsec_unifi"

var (
	// DecisionsProcessed counts decisions that passed the full filter pipeline.
	DecisionsProcessed = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "decisions_processed_total",
		Help:      "Decisions that passed the full filter pipeline.",
	}, []string{"action", "source"})

	// DecisionsFiltered counts decisions rejected per filter stage.
	DecisionsFiltered = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "decisions_filtered_total",
		Help:      "Decisions rejected per filter stage.",
	}, []string{"stage", "reason"})

	// JobsEnqueued counts jobs placed into the worker channel.
	JobsEnqueued = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "jobs_enqueued_total",
		Help:      "Jobs placed into worker channel.",
	}, []string{"action"})

	// JobsDropped counts jobs discarded without an API call.
	JobsDropped = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "jobs_dropped_total",
		Help:      "Jobs discarded without API call.",
	}, []string{"reason"})

	// JobsProcessed counts worker completions.
	JobsProcessed = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "jobs_processed_total",
		Help:      "Worker job completions.",
	}, []string{"action", "status"})

	// APICalls counts raw UniFi API calls.
	APICalls = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "api_calls_total",
		Help:      "Raw UniFi API call counts.",
	}, []string{"endpoint", "status"})

	// APIDuration records UniFi API latency.
	APIDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "api_duration_seconds",
		Help:      "UniFi API call latency in seconds.",
		Buckets:   []float64{0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0},
	}, []string{"endpoint"})

	// AuthErrors counts re-auth calls that failed.
	AuthErrors = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "auth_errors_total",
		Help:      "Re-auth calls that failed.",
	})

	// ReauthTotal counts successful re-auth events.
	ReauthTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "reauth_total",
		Help:      "Successful re-auth events.",
	})

	// ActiveBans is a gauge for current banned IPs per site and family.
	ActiveBans = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "active_bans",
		Help:      "Current banned IPs in bbolt per site.",
	}, []string{"family", "site"})

	// FirewallGroupSize tracks IPs per group shard in UniFi.
	FirewallGroupSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "firewall_group_size",
		Help:      "IPs per firewall group shard in UniFi.",
	}, []string{"family", "shard", "site"})

	// DBSizeBytes tracks bbolt on-disk file size.
	DBSizeBytes = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "db_size_bytes",
		Help:      "bbolt on-disk file size in bytes.",
	})

	// WorkerQueueDepth tracks current job channel length.
	WorkerQueueDepth = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "worker_queue_depth",
		Help:      "Current job channel buffer depth.",
	})

	// ReconcileDuration records full reconcile duration.
	ReconcileDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "reconcile_duration_seconds",
		Help:      "Full reconcile duration in seconds.",
		Buckets:   []float64{0.1, 0.5, 1.0, 5.0, 15.0, 60.0, 300.0},
	}, []string{"trigger"})

	// ReconcileDelta tracks IPs changed in last reconcile.
	ReconcileDelta = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "reconcile_delta",
		Help:      "IPs changed in last reconcile.",
	}, []string{"direction", "site"})
)
