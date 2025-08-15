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
  --format='value(status.url)') \
&& gcloud run services update $SERVICE \
  --platform managed --region $REGION \
  --set-env-vars PUBLIC_BASE_URL=$URL

echo "Deployment complete! Service URL: $URL"