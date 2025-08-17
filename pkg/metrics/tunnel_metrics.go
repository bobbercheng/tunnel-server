package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// TunnelMetrics holds all tunnel-related Prometheus metrics
type TunnelMetrics struct {
	// Request metrics
	RequestsTotal    *prometheus.CounterVec
	RequestDuration  *prometheus.HistogramVec
	RequestSize      *prometheus.HistogramVec
	ResponseSize     *prometheus.HistogramVec

	// WebSocket metrics
	WSConnections    *prometheus.GaugeVec
	WSMessages       *prometheus.CounterVec

	// Custom URL metrics
	CustomURLRequests *prometheus.CounterVec
	SmartRoutingRedirects *prometheus.CounterVec

	// Geographic metrics
	RequestsByCountry *prometheus.CounterVec

	// Error metrics
	ErrorsTotal      *prometheus.CounterVec
}

// NewTunnelMetrics creates and registers all tunnel metrics
func NewTunnelMetrics() *TunnelMetrics {
	return &TunnelMetrics{
		// Request metrics
		RequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "tunnel_requests_total",
				Help: "Total number of tunnel requests",
			},
			[]string{"tunnel_id", "method", "status"},
		),

		RequestDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "tunnel_request_duration_seconds",
				Help:    "Duration of tunnel requests in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"tunnel_id"},
		),

		RequestSize: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "tunnel_request_size_bytes",
				Help:    "Size of tunnel requests in bytes",
				Buckets: prometheus.ExponentialBuckets(100, 10, 6), // 100B to 10MB
			},
			[]string{"tunnel_id"},
		),

		ResponseSize: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "tunnel_response_size_bytes",
				Help:    "Size of tunnel responses in bytes",
				Buckets: prometheus.ExponentialBuckets(100, 10, 6), // 100B to 10MB
			},
			[]string{"tunnel_id"},
		),

		// WebSocket metrics
		WSConnections: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "tunnel_websocket_connections",
				Help: "Number of active WebSocket connections",
			},
			[]string{"tunnel_id"},
		),

		WSMessages: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "tunnel_websocket_messages_total",
				Help: "Total number of WebSocket messages",
			},
			[]string{"tunnel_id", "direction"},
		),

		// Custom URL metrics
		CustomURLRequests: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "tunnel_custom_url_requests_total",
				Help: "Total number of custom URL requests",
			},
			[]string{"custom_url", "status"},
		),

		SmartRoutingRedirects: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "tunnel_smart_routing_redirects_total",
				Help: "Total number of smart routing redirects",
			},
			[]string{"detected_tunnel"},
		),

		// Geographic metrics
		RequestsByCountry: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "tunnel_requests_by_country",
				Help: "Total number of requests by country",
			},
			[]string{"tunnel_id", "country"},
		),

		// Error metrics
		ErrorsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "tunnel_errors_total",
				Help: "Total number of tunnel errors",
			},
			[]string{"tunnel_id", "error_type"},
		),
	}
}

// RecordRequest records a tunnel request with all relevant metrics
func (m *TunnelMetrics) RecordRequest(tunnelID, method, status string, duration float64, requestSize, responseSize int64) {
	m.RequestsTotal.WithLabelValues(tunnelID, method, status).Inc()
	m.RequestDuration.WithLabelValues(tunnelID).Observe(duration)
	m.RequestSize.WithLabelValues(tunnelID).Observe(float64(requestSize))
	m.ResponseSize.WithLabelValues(tunnelID).Observe(float64(responseSize))
}

// RecordCustomURLRequest records a custom URL request
func (m *TunnelMetrics) RecordCustomURLRequest(customURL, status string) {
	m.CustomURLRequests.WithLabelValues(customURL, status).Inc()
}

// RecordSmartRoutingRedirect records a smart routing redirect
func (m *TunnelMetrics) RecordSmartRoutingRedirect(detectedTunnel string) {
	m.SmartRoutingRedirects.WithLabelValues(detectedTunnel).Inc()
}

// RecordGeographicRequest records a request with geographic information
func (m *TunnelMetrics) RecordGeographicRequest(tunnelID, country string) {
	m.RequestsByCountry.WithLabelValues(tunnelID, country).Inc()
}

// RecordError records an error
func (m *TunnelMetrics) RecordError(tunnelID, errorType string) {
	m.ErrorsTotal.WithLabelValues(tunnelID, errorType).Inc()
}

// IncrementWSConnection increments WebSocket connection count
func (m *TunnelMetrics) IncrementWSConnection(tunnelID string) {
	m.WSConnections.WithLabelValues(tunnelID).Inc()
}

// DecrementWSConnection decrements WebSocket connection count
func (m *TunnelMetrics) DecrementWSConnection(tunnelID string) {
	m.WSConnections.WithLabelValues(tunnelID).Dec()
}

// RecordWSMessage records a WebSocket message
func (m *TunnelMetrics) RecordWSMessage(tunnelID, direction string) {
	m.WSMessages.WithLabelValues(tunnelID, direction).Inc()
}