# Usage Tracking Implementation Plan

## Overview
Implement comprehensive usage tracking and reporting for the GCP reverse-tunnel HTTP proxy system to provide tunnel operators with detailed analytics about their service usage.

## Architecture Decision: Prometheus → OpenTelemetry Migration Path

After analyzing trade-offs between Prometheus and OpenTelemetry, we've chosen a **phased approach**:

### Why Start with Prometheus?
- **Low complexity**: Simpler integration with existing Go codebase
- **Cloud Run native**: Excellent integration with Google Cloud Monitoring
- **Performance**: Minimal overhead for tunnel throughput (critical requirement)
- **Operational simplicity**: No additional infrastructure required
- **Immediate value**: Quick implementation for core metrics

### Why Migrate to OpenTelemetry Later?
- **Future-proofing**: Industry standard for observability
- **Vendor neutrality**: Avoid lock-in to specific monitoring solutions
- **Rich ecosystem**: Better support for traces, logs, and complex analytics
- **Advanced features**: Distributed tracing for complex routing decisions

## Implementation Phases

### Phase 1: Prometheus Foundation (Week 1 - CURRENT)
**Goal**: Basic usage metrics with Cloud Run monitoring integration

**Deliverables**:
- ✅ Core metrics instrumentation (requests, bandwidth, latency, errors)
- ✅ `/metrics` endpoint for Prometheus scraping
- ✅ Cloud Run monitoring integration
- ✅ Per-tunnel usage tracking

**Key Metrics**:
```prometheus
# Request metrics
tunnel_requests_total{tunnel_id, method, status}
tunnel_request_duration_seconds{tunnel_id}
tunnel_request_size_bytes{tunnel_id}
tunnel_response_size_bytes{tunnel_id}

# Connection metrics  
tunnel_websocket_connections{tunnel_id}
tunnel_websocket_messages_total{tunnel_id, direction}

# Custom URL metrics
tunnel_custom_url_requests_total{custom_url, status}
tunnel_smart_routing_redirects_total{detected_tunnel}

# Geographic metrics
tunnel_requests_by_country{tunnel_id, country}
```

**Files Modified**:
- `server/go.mod` - Add Prometheus client library
- `pkg/metrics/` - New package for shared metric definitions
- `server/handlers.go` - Instrument publicHandler and custom URL handlers
- `server/websocket.go` - Instrument WebSocket connection and message metrics
- `server/client_tracking.go` - Add smart routing metrics
- `server/main.go` - Add /metrics endpoint
- `server/Dockerfile` - Expose metrics port

### Phase 2: Enhanced Analytics (Week 2-3)
**Goal**: Rich per-tunnel analytics and reporting

**Deliverables**:
- Geographic usage breakdown using existing IP geolocation
- Custom URL performance analytics
- Client fingerprinting usage patterns
- Smart routing effectiveness metrics
- Basic usage reporting API (`/__usage__/` endpoint)

**New Metrics**:
```prometheus
# Advanced analytics
tunnel_geographic_distribution{tunnel_id, country, city}
tunnel_client_types{tunnel_id, client_fingerprint}
tunnel_asset_cache_hits{tunnel_id}
tunnel_routing_confidence{tunnel_id, confidence_level}
```

### Phase 3: OpenTelemetry Tracing (Month 2)
**Goal**: Distributed tracing for complex routing decisions

**Deliverables**:
- OpenTelemetry integration alongside Prometheus metrics
- Distributed tracing for request flow through smart routing
- Google Cloud Trace integration
- Trace correlation with metrics

**Tracing Spans**:
- `tunnel.request` - Full request lifecycle
- `tunnel.smart_routing` - Client fingerprinting and routing decisions
- `tunnel.websocket_forward` - Message forwarding to agent
- `tunnel.custom_url_resolution` - Custom URL to tunnel mapping

### Phase 4: Advanced Reporting & Analytics (Month 3)
**Goal**: Business intelligence and automated insights

**Deliverables**:
- Historical usage trends and forecasting
- Automated usage reports (daily/weekly/monthly)
- Performance optimization recommendations
- Usage-based alerting and quotas
- BigQuery integration for advanced analytics

### Phase 5: Full OpenTelemetry Migration (Month 4+)
**Goal**: Unified observability platform

**Evaluation Criteria**:
- Team operational capacity for managing OpenTelemetry
- Value demonstrated by tracing in Phase 3
- Vendor flexibility requirements
- Performance impact assessment

**Migration Path**:
- Gradual replacement of Prometheus metrics with OpenTelemetry metrics
- Unified observability pipeline (metrics + traces + logs)
- Vendor-neutral observability stack

## Success Metrics

### Phase 1 Success Criteria:
- [ ] `/metrics` endpoint returning valid Prometheus format
- [ ] Google Cloud Monitoring receiving tunnel metrics
- [ ] Per-tunnel usage data available in Cloud Console
- [ ] <5ms latency impact on tunnel requests
- [ ] No memory leaks or resource exhaustion

### Overall Success Criteria:
- Tunnel operators can view detailed usage statistics
- Geographic and performance analytics available
- Automated alerting for unusual usage patterns
- Historical trend analysis for capacity planning
- <1% performance impact on tunnel throughput

## Risk Mitigation

### Performance Risks:
- **Metric cardinality explosion**: Limit labels and use sampling for high-volume metrics
- **Memory usage**: Implement metric rotation and limits
- **Latency impact**: Asynchronous metric collection where possible

### Operational Risks:
- **Cloud Run scaling**: Ensure metrics work correctly during auto-scaling
- **Data loss**: Design for ephemeral Cloud Run instances
- **Monitoring costs**: Monitor Cloud Monitoring usage and optimize metric frequency

### Technical Risks:
- **Integration complexity**: Start simple, add complexity gradually
- **Backward compatibility**: Maintain existing APIs while adding metrics
- **Debugging overhead**: Ensure metrics don't interfere with existing logging

## Implementation Guidelines

### Code Standards:
- Follow existing Go workspace patterns (`go.work`)
- Use existing error handling and logging patterns
- Maintain thread safety with existing mutex patterns
- Add comprehensive unit tests for all new metrics

### Metric Design Principles:
- **Consistent labeling**: Use `tunnel_id`, `custom_url`, `client_id` consistently
- **Appropriate cardinality**: Avoid high-cardinality labels (no request IDs)
- **Meaningful names**: Follow Prometheus naming conventions
- **Documentation**: Clear descriptions for all metrics

### Testing Strategy:
- Unit tests for metric collection logic
- Integration tests with Cloud Run deployment
- Load testing to verify performance impact
- Monitoring validation in staging environment

## Dependencies

### External Libraries:
- `github.com/prometheus/client_golang` - Prometheus client
- `go.opentelemetry.io/otel` - OpenTelemetry (Phase 3+)
- Existing: IP geolocation database, WebSocket libraries

### Infrastructure:
- Google Cloud Monitoring (included with Cloud Run)
- Google Cloud Trace (Phase 3+)
- BigQuery (Phase 4+)

### Team Requirements:
- Go development experience
- Basic Prometheus/observability knowledge
- Google Cloud Platform familiarity

---

## Status Tracking

**Current Phase**: Phase 1 - Prometheus Foundation  
**Started**: 2025-08-17  
**Target Completion**: 2025-08-20  

**Next Review**: After Phase 1 completion to assess OpenTelemetry migration timeline