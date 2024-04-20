package server

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var allowedCounter = promauto.NewCounter(
	prometheus.CounterOpts{
		Name: "jarl_allowed_request_count",
		Help: "No of allowed accepted",
	},
)

var deniedCounter = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "jarl_denied_request_count",
		Help: "No of request denied",
	},
	[]string{"client_id"},
)
