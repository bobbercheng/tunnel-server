#!/bin/bash

# Script to test geographical routing after deployment

if [ -z "$1" ]; then
    echo "Usage: $0 <server-url>"
    echo "Example: $0 https://tunnel-server-3w6u4kmniq-ue.a.run.app"
    exit 1
fi

SERVER_URL="$1"

echo "🌍 Testing geographical routing deployment at $SERVER_URL"
echo ""

# Test 1: Check health endpoint for geo routing info
echo "1️⃣  Testing health endpoint..."
HEALTH_RESPONSE=$(curl -s "$SERVER_URL/__health__" | jq '.geographical_routing // "not available"')
echo "Geographical routing status: $HEALTH_RESPONSE"
echo ""

# Test 2: Check if server logs indicate GeoIP database loaded
echo "2️⃣  Testing registration endpoint (should work without geo features)..."
REGISTER_RESPONSE=$(curl -s -X POST "$SERVER_URL/__register__" \
    -H "Content-Type: application/json" \
    -d '{"protocol": "http"}')
echo "Registration response: $(echo $REGISTER_RESPONSE | jq -r '.public_url // "error"')"
echo ""

# Test 3: Test a request with geographical headers
echo "3️⃣  Testing request with geographical indicators..."
curl -s -H "X-Forwarded-For: 8.8.8.8" \
     -H "User-Agent: GeoTest/1.0" \
     -H "Accept-Language: en-US,en;q=0.9" \
     "$SERVER_URL/__health__" | jq '.geographical_routing.geoip_available // "unknown"' | \
     while read available; do
         if [ "$available" = "true" ]; then
             echo "✅ GeoIP database is available and working!"
         elif [ "$available" = "false" ]; then
             echo "❌ GeoIP database not available"
         else
             echo "⚠️  Could not determine GeoIP status"
         fi
     done

echo ""
echo "🎯 To further test geographical routing:"
echo "1. Register a tunnel and connect an agent"
echo "2. Make requests from different geographical locations"  
echo "3. Check /__health__ endpoint to see IP mappings and geo preferences build up"
echo ""
echo "Example commands after setting up a tunnel:"
echo "  # From different IPs, make requests to your tunnel"
echo "  curl -H \"X-Forwarded-For: 8.8.8.8\" $SERVER_URL/__pub__/\$TUNNEL_ID/"
echo "  curl -H \"X-Forwarded-For: 1.2.3.4\" $SERVER_URL/__pub__/\$TUNNEL_ID/"
echo ""
echo "  # Check geographical routing stats"
echo "  curl $SERVER_URL/__health__ | jq '.geographical_routing'"