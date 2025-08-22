# Implementation Plan: Custom URL-Based Tunnel Affinity

## Phase 1: Foundation (Week 1) 🏗️

### 1.1 Data Structure Design
**New file: `affinity.go`**
```go
type CustomURLAffinity struct {
    TunnelID     string    `json:"tunnel_id"`
    CustomURL    string    `json:"custom_url"`
    CreatedAt    time.Time `json:"created_at"`
    LastAccess   time.Time `json:"last_access"`
    AccessCount  int       `json:"access_count"`
    Source       string    `json:"source"` // "custom_url_visit", "redirect_session"
}

type AffinityManager struct {
    affinities map[string]*CustomURLAffinity // clientKey -> affinity
    mutex      sync.RWMutex
    metrics    *AffinityMetrics
}
```

### 1.2 Core Affinity Management
```go
func (am *AffinityManager) SetAffinity(clientKey, tunnelID, customURL, source string)
func (am *AffinityManager) GetAffinity(clientKey string) *CustomURLAffinity
func (am *AffinityManager) ClearAffinity(clientKey string)
func (am *AffinityManager) ClearTunnelAffinities(tunnelID string)
```

### 1.3 Integration Points
- Add `affinityManager` to global variables
- Initialize in `main.go`
- Add affinity metrics to health endpoint

## Phase 2: Basic Integration (Week 2) 🔌

### 2.1 Custom URL Handler Enhancement
**Modify `customURLHandler` in `handlers.go`:**
```go
// When custom URL match succeeds:
if tryTunnelRouteWithTimeout(w, newReq, tunnelID, false) {
    // NEW: Set custom URL affinity
    clientKey := generateClientKey(r)
    affinityManager.SetAffinity(clientKey, tunnelID, path, "custom_url_visit")
    log.Printf("[AFFINITY] Set custom URL affinity | ClientKey: %s | TunnelID: %s | CustomURL: %s", 
               clientKey, tunnelID, path)
    return
}
```

### 2.2 Smart Fallback Enhancement  
**Add affinity check to `smartFallbackHandler` in `utils.go`:**
```go
// NEW: Priority check for custom URL affinity (before existing strategies)
if affinity := affinityManager.GetAffinity(clientKey); affinity != nil {
    log.Printf("[AFFINITY] Using custom URL affinity | ClientKey: %s | TunnelID: %s | CustomURL: %s", 
               clientKey, affinity.TunnelID, affinity.CustomURL)
    
    if tryTunnelRouteWithBufferedBody(w, r, bodyBytes, affinity.TunnelID, isAsset) {
        affinityManager.UpdateAccess(clientKey) // Update last access time
        return
    } else {
        // Tunnel failed - clear affinity and continue to fallbacks
        log.Printf("[AFFINITY] Tunnel failed, clearing affinity | ClientKey: %s | TunnelID: %s", 
                   clientKey, affinity.TunnelID)
        affinityManager.ClearAffinity(clientKey)
    }
}
```

### 2.3 Cleanup Integration
**Add to existing cleanup routines:**
```go
// In main.go cleanup goroutine:
go func() {
    ticker := time.NewTicker(1 * time.Hour)
    defer ticker.Stop()
    for range ticker.C {
        affinityManager.CleanupInactiveAffinities(24 * time.Hour)
        affinityManager.CleanupDisconnectedTunnels()
    }
}()
```

## Phase 3: Robustness (Week 3) 🛡️

### 3.1 Enhanced Client Tracking
**Improve client fingerprinting resilience:**
```go
func generateEnhancedClientKey(r *http.Request) string {
    // Primary fingerprint
    primary := generateClientKey(r)
    
    // Fallback fingerprints for consistency
    fallbacks := []string{
        generateIPUserAgentKey(r),
        generateSessionKey(r), // from cookies if available
    }
    
    return primary // Store all variants for lookup
}
```

### 3.2 Tunnel Disconnection Handling
**Add to websocket disconnection logic:**
```go
// In websocket.go when agent disconnects:
func (ac *agentConn) cleanup() {
    // Existing cleanup...
    
    // NEW: Clear affinities for this tunnel
    affinityManager.ClearTunnelAffinities(ac.tunnelID)
    log.Printf("[AFFINITY] Cleared affinities for disconnected tunnel | TunnelID: %s", ac.tunnelID)
}
```

### 3.3 Hybrid Fallback Strategy
**Ensure graceful degradation:**
```go
func smartAffinityRouting(w http.ResponseWriter, r *http.Request, clientKey string, bodyBytes []byte) bool {
    affinity := affinityManager.GetAffinity(clientKey)
    if affinity == nil {
        return false // No affinity, use existing fallbacks
    }
    
    // Try affinity tunnel with shorter timeout
    if tryTunnelRouteWithTimeout(w, r, affinity.TunnelID, 5*time.Second) {
        affinityManager.UpdateAccess(clientKey)
        return true
    }
    
    // Affinity failed - check if tunnel still exists
    if !isTunnelActive(affinity.TunnelID) {
        affinityManager.ClearAffinity(clientKey)
        log.Printf("[AFFINITY] Cleared affinity for inactive tunnel | ClientKey: %s", clientKey)
    }
    
    return false // Fall back to existing logic
}
```

## Phase 4: Advanced Features (Week 4) 🚀

### 4.1 Enhanced Health Endpoint
**Add affinity debugging to `/__health__`:**
```go
type HealthResponse struct {
    // Existing fields...
    CustomURLAffinity AffinityStats `json:"custom_url_affinity"`
}

type AffinityStats struct {
    ActiveAffinities  int                    `json:"active_affinities"`
    AffinitiesByURL   map[string]int         `json:"affinities_by_url"`
    RouteHitRate      float64               `json:"route_hit_rate"`
    AverageAge        string                `json:"average_age"`
    RecentActivity    []AffinityActivity    `json:"recent_activity"`
}
```

### 4.2 Affinity Reset Endpoint
**Add debugging endpoint:**
```go
// GET /__debug__/affinity?client_key=xxx
func affinityDebugHandler(w http.ResponseWriter, r *http.Request) {
    clientKey := r.URL.Query().Get("client_key")
    if clientKey == "" {
        clientKey = generateClientKey(r)
    }
    
    affinity := affinityManager.GetAffinity(clientKey)
    json.NewEncoder(w).Encode(map[string]interface{}{
        "client_key": clientKey,
        "affinity":   affinity,
        "actions":    []string{"reset", "refresh"},
    })
}
```

### 4.3 Metrics Integration
**Add Prometheus metrics:**
```go
var (
    affinityHits = prometheus.NewCounterVec(
        prometheus.CounterOpts{Name: "tunnel_affinity_hits_total"},
        []string{"custom_url", "tunnel_id"},
    )
    affinityMisses = prometheus.NewCounterVec(
        prometheus.CounterOpts{Name: "tunnel_affinity_misses_total"},
        []string{"reason"},
    )
)
```

## Phase 5: Testing & Validation (Week 5) 🧪

### 5.1 Unit Tests
```go
func TestAffinityManager_SetAndGet(t *testing.T)
func TestAffinityManager_TunnelDisconnection(t *testing.T)
func TestAffinityRouting_SingleTunnel(t *testing.T)
func TestAffinityRouting_MultipleTunnels(t *testing.T)
func TestAffinityFallback_TunnelFailure(t *testing.T)
```

### 5.2 Integration Tests
```go
func TestCustomURLAffinity_LibreChatWorkflow(t *testing.T)
func TestMultiTenant_AffinitySeparation(t *testing.T)
func TestBrowserFingerprint_Consistency(t *testing.T)
```

### 5.3 Load Testing
- Simulate multiple users across different custom URLs
- Test affinity persistence under heavy load  
- Validate memory usage and cleanup efficiency

## Phase 6: Deployment & Monitoring (Week 6) 📊

### 6.1 Feature Flag Implementation
```go
var enableCustomURLAffinity = os.Getenv("ENABLE_CUSTOM_URL_AFFINITY") == "true"

// Gradual rollout with fallback
if enableCustomURLAffinity && smartAffinityRouting(...) {
    return // Success
}
// Fall back to existing logic
```

### 6.2 Monitoring Dashboard
- Affinity hit/miss rates
- Average affinity age
- Memory usage trends
- User experience metrics

### 6.3 Rollback Plan
- Feature flag disable
- Graceful degradation to existing logic
- Affinity state preservation option

## Success Metrics 📈

### Performance Goals
- **Routing latency**: 50% reduction for affinity hits
- **Server load**: 30% reduction in complex fallback routing
- **User experience**: 95%+ of API calls route correctly

### Reliability Targets  
- **Affinity accuracy**: 99%+ correct routing
- **Fallback success**: 100% graceful degradation
- **Memory efficiency**: <1MB per 1000 active users

## Risk Mitigation 🎯

### High-Priority Risks
1. **Memory leaks**: Aggressive cleanup + monitoring
2. **Routing failures**: Hybrid fallback approach
3. **State loss**: Graceful degradation on restarts
4. **User confusion**: Clear debugging tools

### Rollback Triggers
- Affinity hit rate <80%
- Memory usage >10MB
- User-reported routing issues
- Performance degradation >20%

This phased approach ensures safe, testable implementation with clear rollback options at each stage.