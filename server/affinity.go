package main

import (
	"sync"
	"time"
	"log"
)

// CustomURLAffinity represents a client's affinity to a specific tunnel based on custom URL access
type CustomURLAffinity struct {
	TunnelID     string    `json:"tunnel_id"`
	CustomURL    string    `json:"custom_url"`
	CreatedAt    time.Time `json:"created_at"`
	LastAccess   time.Time `json:"last_access"`
	AccessCount  int       `json:"access_count"`
	Source       string    `json:"source"` // "custom_url_visit", "redirect_session"
}

// AffinityMetrics tracks statistics about affinity usage
type AffinityMetrics struct {
	TotalAffinities    int     `json:"total_affinities"`
	HitCount          int     `json:"hit_count"`
	MissCount         int     `json:"miss_count"`
	HitRate           float64 `json:"hit_rate"`
	AffinitiesByURL   map[string]int `json:"affinities_by_url"`
	RecentActivity    []AffinityActivity `json:"recent_activity"`
}

// AffinityActivity represents recent affinity-related events
type AffinityActivity struct {
	Timestamp   time.Time `json:"timestamp"`
	Action      string    `json:"action"` // "created", "used", "cleared", "expired"
	ClientKey   string    `json:"client_key"`
	TunnelID    string    `json:"tunnel_id"`
	CustomURL   string    `json:"custom_url"`
	Reason      string    `json:"reason,omitempty"`
	ClientIP    string    `json:"client_ip,omitempty"`
	Country     string    `json:"country,omitempty"`
	Region      string    `json:"region,omitempty"`
	City        string    `json:"city,omitempty"`
}

// AffinityManager manages client-to-tunnel affinities based on custom URL access
type AffinityManager struct {
	affinities map[string]*CustomURLAffinity // clientKey -> affinity
	mutex      sync.RWMutex
	metrics    *AffinityMetrics
}

// NewAffinityManager creates a new affinity manager
func NewAffinityManager() *AffinityManager {
	return &AffinityManager{
		affinities: make(map[string]*CustomURLAffinity),
		metrics: &AffinityMetrics{
			AffinitiesByURL: make(map[string]int),
			RecentActivity:  make([]AffinityActivity, 0),
		},
	}
}

// SetAffinity creates or updates a client's affinity to a tunnel
func (am *AffinityManager) SetAffinity(clientKey, tunnelID, customURL, source string) {
	am.SetAffinityWithIP(clientKey, tunnelID, customURL, source, "")
}

// SetAffinityWithIP creates or updates a client's affinity to a tunnel with client IP for geo tracking
func (am *AffinityManager) SetAffinityWithIP(clientKey, tunnelID, customURL, source, clientIP string) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	now := time.Now()
	
	// Check if affinity already exists
	existing, exists := am.affinities[clientKey]
	if exists {
		// Update existing affinity
		existing.TunnelID = tunnelID
		existing.CustomURL = customURL
		existing.LastAccess = now
		existing.Source = source
		
		log.Printf("[AFFINITY] Updated affinity | ClientKey: %s | TunnelID: %s | CustomURL: %s | Source: %s", 
				   clientKey, tunnelID, customURL, source)
	} else {
		// Create new affinity
		affinity := &CustomURLAffinity{
			TunnelID:    tunnelID,
			CustomURL:   customURL,
			CreatedAt:   now,
			LastAccess:  now,
			AccessCount: 0,
			Source:      source,
		}
		am.affinities[clientKey] = affinity
		am.metrics.TotalAffinities++
		
		log.Printf("[AFFINITY] Created new affinity | ClientKey: %s | TunnelID: %s | CustomURL: %s | Source: %s", 
				   clientKey, tunnelID, customURL, source)
	}

	// Lookup geolocation data if client IP is provided
	var geoData *IPGeoData
	if clientIP != "" {
		geoData = lookupIPGeoData(clientIP)
	}

	// Update metrics
	am.metrics.AffinitiesByURL[customURL]++
	am.addActivityWithGeo("created", clientKey, tunnelID, customURL, "", clientIP, geoData)
}

// GetAffinity retrieves a client's current affinity
func (am *AffinityManager) GetAffinity(clientKey string) *CustomURLAffinity {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	affinity, exists := am.affinities[clientKey]
	if !exists {
		am.metrics.MissCount++
		am.updateHitRate()
		return nil
	}

	am.metrics.HitCount++
	am.updateHitRate()
	return affinity
}

// GetValidatedAffinity retrieves and validates a client's affinity, returning nil if invalid
func (am *AffinityManager) GetValidatedAffinity(clientKey string) *CustomURLAffinity {
	affinity := am.GetAffinity(clientKey)
	if affinity == nil {
		return nil
	}

	// Validate that the tunnel still exists and has the correct custom URL
	tunnelCustomURL := getTunnelCustomURL(affinity.TunnelID)
	if tunnelCustomURL == "" {
		// Tunnel no longer exists, clear invalid affinity
		log.Printf("[AFFINITY] Clearing invalid affinity - tunnel no longer exists | ClientKey: %s | TunnelID: %s", 
				   clientKey, affinity.TunnelID)
		am.ClearAffinity(clientKey)
		return nil
	}

	if tunnelCustomURL != affinity.CustomURL {
		// Custom URL mismatch, clear contaminated affinity
		log.Printf("[AFFINITY] Clearing contaminated affinity - CustomURL mismatch | ClientKey: %s | TunnelID: %s | Expected: %s | Stored: %s", 
				   clientKey, affinity.TunnelID, tunnelCustomURL, affinity.CustomURL)
		am.ClearAffinity(clientKey)
		return nil
	}

	return affinity
}

// UpdateAccess updates the last access time and increments access count
func (am *AffinityManager) UpdateAccess(clientKey string) {
	am.UpdateAccessWithIP(clientKey, "")
}

// UpdateAccessWithIP updates access with client IP for geo tracking
func (am *AffinityManager) UpdateAccessWithIP(clientKey, clientIP string) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	affinity, exists := am.affinities[clientKey]
	if exists {
		affinity.LastAccess = time.Now()
		affinity.AccessCount++

		// Lookup geolocation data if client IP is provided
		var geoData *IPGeoData
		if clientIP != "" {
			geoData = lookupIPGeoData(clientIP)
		}

		am.addActivityWithGeo("used", clientKey, affinity.TunnelID, affinity.CustomURL, "", clientIP, geoData)
	}
}

// ClearAffinity removes a client's affinity
func (am *AffinityManager) ClearAffinity(clientKey string) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	affinity, exists := am.affinities[clientKey]
	if exists {
		delete(am.affinities, clientKey)
		am.metrics.TotalAffinities--
		am.addActivity("cleared", clientKey, affinity.TunnelID, affinity.CustomURL, "manual_clear")
		
		log.Printf("[AFFINITY] Cleared affinity | ClientKey: %s | TunnelID: %s | CustomURL: %s", 
				   clientKey, affinity.TunnelID, affinity.CustomURL)
	}
}

// ClearTunnelAffinities removes all affinities for a specific tunnel (when tunnel disconnects)
func (am *AffinityManager) ClearTunnelAffinities(tunnelID string) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	clearedCount := 0
	for clientKey, affinity := range am.affinities {
		if affinity.TunnelID == tunnelID {
			delete(am.affinities, clientKey)
			am.metrics.TotalAffinities--
			am.addActivity("cleared", clientKey, tunnelID, affinity.CustomURL, "tunnel_disconnect")
			clearedCount++
		}
	}

	if clearedCount > 0 {
		log.Printf("[AFFINITY] Cleared %d affinities for disconnected tunnel | TunnelID: %s", clearedCount, tunnelID)
	}
}

// CleanupInactiveAffinities removes affinities that haven't been accessed for the specified duration
func (am *AffinityManager) CleanupInactiveAffinities(maxAge time.Duration) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	now := time.Now()
	expiredCount := 0

	for clientKey, affinity := range am.affinities {
		if now.Sub(affinity.LastAccess) > maxAge {
			delete(am.affinities, clientKey)
			am.metrics.TotalAffinities--
			am.addActivity("cleared", clientKey, affinity.TunnelID, affinity.CustomURL, "expired")
			expiredCount++
		}
	}

	if expiredCount > 0 {
		log.Printf("[AFFINITY] Cleaned up %d expired affinities (max age: %v)", expiredCount, maxAge)
	}
}

// CleanupDisconnectedTunnels removes affinities for tunnels that no longer exist
func (am *AffinityManager) CleanupDisconnectedTunnels() {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	// Get current active tunnel IDs
	activeTunnelIDs := getActiveTunnelIDs()
	activeTunnels := make(map[string]bool)
	for _, id := range activeTunnelIDs {
		activeTunnels[id] = true
	}

	clearedCount := 0
	for clientKey, affinity := range am.affinities {
		if !activeTunnels[affinity.TunnelID] {
			delete(am.affinities, clientKey)
			am.metrics.TotalAffinities--
			am.addActivity("cleared", clientKey, affinity.TunnelID, affinity.CustomURL, "tunnel_not_found")
			clearedCount++
		}
	}

	if clearedCount > 0 {
		log.Printf("[AFFINITY] Cleaned up %d affinities for disconnected tunnels", clearedCount)
	}
}

// GetMetrics returns current affinity metrics
func (am *AffinityManager) GetMetrics() *AffinityMetrics {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	// Create a copy to avoid race conditions
	metrics := &AffinityMetrics{
		TotalAffinities:  am.metrics.TotalAffinities,
		HitCount:        am.metrics.HitCount,
		MissCount:       am.metrics.MissCount,
		HitRate:         am.metrics.HitRate,
		AffinitiesByURL: make(map[string]int),
		RecentActivity:  make([]AffinityActivity, len(am.metrics.RecentActivity)),
	}

	// Copy maps and slices
	for k, v := range am.metrics.AffinitiesByURL {
		metrics.AffinitiesByURL[k] = v
	}
	copy(metrics.RecentActivity, am.metrics.RecentActivity)

	return metrics
}

// GetAffinityStats returns detailed affinity statistics
func (am *AffinityManager) GetAffinityStats() map[string]interface{} {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	stats := make(map[string]interface{})
	stats["active_affinities"] = am.metrics.TotalAffinities
	stats["hit_rate"] = am.metrics.HitRate
	stats["affinities_by_url"] = am.metrics.AffinitiesByURL

	// Calculate average age
	if len(am.affinities) > 0 {
		totalAge := time.Duration(0)
		now := time.Now()
		for _, affinity := range am.affinities {
			totalAge += now.Sub(affinity.CreatedAt)
		}
		avgAge := totalAge / time.Duration(len(am.affinities))
		stats["average_age"] = avgAge.String()
	} else {
		stats["average_age"] = "N/A"
	}

	// Recent activity (last 10 events)
	recentCount := 10
	if len(am.metrics.RecentActivity) < recentCount {
		recentCount = len(am.metrics.RecentActivity)
	}
	if recentCount > 0 {
		start := len(am.metrics.RecentActivity) - recentCount
		stats["recent_activity"] = am.metrics.RecentActivity[start:]
	} else {
		stats["recent_activity"] = []AffinityActivity{}
	}

	return stats
}

// Helper method to update hit rate
func (am *AffinityManager) updateHitRate() {
	total := am.metrics.HitCount + am.metrics.MissCount
	if total > 0 {
		am.metrics.HitRate = float64(am.metrics.HitCount) / float64(total)
	}
}

// Helper method to add activity (keeps last 100 events)
func (am *AffinityManager) addActivity(action, clientKey, tunnelID, customURL, reason string) {
	am.addActivityWithGeo(action, clientKey, tunnelID, customURL, reason, "", nil)
}

// addActivityWithGeo adds activity with client IP and geolocation information
func (am *AffinityManager) addActivityWithGeo(action, clientKey, tunnelID, customURL, reason, clientIP string, geoData *IPGeoData) {
	activity := AffinityActivity{
		Timestamp: time.Now(),
		Action:    action,
		ClientKey: clientKey,
		TunnelID:  tunnelID,
		CustomURL: customURL,
		Reason:    reason,
		ClientIP:  clientIP,
	}

	// Add geolocation data if available
	if geoData != nil {
		activity.Country = geoData.Country
		activity.Region = geoData.Region
		activity.City = geoData.City
	}

	am.metrics.RecentActivity = append(am.metrics.RecentActivity, activity)

	// Keep only last 100 events to prevent memory growth
	if len(am.metrics.RecentActivity) > 100 {
		am.metrics.RecentActivity = am.metrics.RecentActivity[1:]
	}
}