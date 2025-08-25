#!/bin/bash
set -e

export PROJECT_ID=contact-center-insights-poc
export REGION=us-east1
export SERVICE=tunnel-server
export IMAGE_NAME=gcr.io/$PROJECT_ID/tunnel-server

# Build using Cloud Build from parent directory to include crypto package and GeoLite2 database
echo "Building Docker image using Cloud Build..."
cd ..

# Copy Dockerfile to parent directory as expected name
cp server/Dockerfile ./Dockerfile

# Submit build 
gcloud builds submit --tag $IMAGE_NAME .

# Clean up
rm ./Dockerfile

# Deploy to Cloud Run
echo "Deploying to Cloud Run..."
URL=$(gcloud run deploy $SERVICE \
  --image $IMAGE_NAME \
  --platform managed --region $REGION \
  --allow-unauthenticated --max-instances=1 \
  --timeout=3600 \
  --format='value(status.url)') \
&& gcloud run services update $SERVICE \
  --platform managed --region $REGION \
  --set-env-vars PUBLIC_BASE_URL=https://connect.vexorium.net \
  --update-annotations="prometheus.io/scrape=true,prometheus.io/path=/__metrics__,prometheus.io/port=8080"

echo "Deployment complete! Service URL: $URL"

# Verify metrics endpoint is working
echo ""
echo "🔍 Verifying metrics endpoint..."
sleep 5  # Give the service a moment to start

METRICS_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "$URL/__metrics__")
if [ "$METRICS_RESPONSE" = "200" ]; then
    echo "✅ Metrics endpoint is working: $URL/__metrics__"
    
    # Check if tunnel metrics are available
    TUNNEL_METRICS=$(curl -s "$URL/__metrics__" | grep -c "tunnel_" || true)
    if [ "$TUNNEL_METRICS" -gt 0 ]; then
        echo "✅ Found $TUNNEL_METRICS tunnel metric types"
    else
        echo "ℹ️  No tunnel metrics yet (will appear with tunnel activity)"
    fi
else
    echo "❌ Metrics endpoint check failed (HTTP $METRICS_RESPONSE)"
fi

echo ""
echo "📊 Google Cloud Monitoring setup:"
echo "   • Prometheus scraping: ENABLED"
echo "   • Metrics path: /__metrics__"
echo "   • Metrics should appear in Cloud Monitoring within 10-20 minutes"
echo ""
echo "🔗 Useful links:"
echo "   • Service URL: $URL"
echo "   • Health check: $URL/__health__"
echo "   • Metrics endpoint: $URL/__metrics__"
echo "   • Cloud Monitoring: https://console.cloud.google.com/monitoring/metrics-explorer?project=$PROJECT_ID"