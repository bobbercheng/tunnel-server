#!/bin/bash
set -e

# Configuration
PROJECT_ID="contact-center-insights-poc"
SERVICE_ACCOUNT_NAME="gitlab-ci-deployment"
SERVICE_ACCOUNT_EMAIL="${SERVICE_ACCOUNT_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

echo "Updating GCP Service Account permissions for GitHub CI/CD..."

# Check if service account exists
if ! gcloud iam service-accounts describe $SERVICE_ACCOUNT_EMAIL --project=$PROJECT_ID >/dev/null 2>&1; then
    echo "❌ Service account not found: $SERVICE_ACCOUNT_EMAIL"
    echo "Please run setup-gcp-service-account.sh first to create the service account."
    exit 1
fi

echo "✅ Service account found: $SERVICE_ACCOUNT_EMAIL"

# Check and enable required APIs
echo "Checking required APIs..."

REQUIRED_APIS=(
    "cloudbuild.googleapis.com"
    "run.googleapis.com"
    "serviceusage.googleapis.com"
    "storage.googleapis.com"
)

for API in "${REQUIRED_APIS[@]}"; do
    if gcloud services list --enabled --filter="name:$API" --format="value(name)" --project=$PROJECT_ID | grep -q "$API"; then
        echo "  ✅ $API (already enabled)"
    else
        echo "  🔧 Enabling $API..."
        gcloud services enable $API --project=$PROJECT_ID
    fi
done

# Add the missing roles
echo "Adding missing IAM roles..."

# Service Usage Consumer - needed for Cloud Build and other service usage
echo "  - Service Usage Consumer"
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SERVICE_ACCOUNT_EMAIL" \
    --role="roles/serviceusage.serviceUsageConsumer" \
    --quiet

# Storage Admin - upgrade from objectAdmin to full storage admin for Cloud Build buckets
echo "  - Storage Admin (upgrading from Object Admin)"
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SERVICE_ACCOUNT_EMAIL" \
    --role="roles/storage.admin" \
    --quiet

echo ""
echo "✅ Service account permissions updated successfully!"
echo ""
echo "🔍 Current permissions for service account:"
gcloud projects get-iam-policy $PROJECT_ID --flatten="bindings[].members" --filter="bindings.members:$SERVICE_ACCOUNT_EMAIL" --format="table(bindings.role)"
echo ""
echo "🚀 Your GitHub Action should now work correctly for Cloud Build deployments."
echo ""
echo "💡 If you're still having issues, make sure:"
echo "   1. The GitHub secret GCP_SERVICE_ACCOUNT_KEY contains the correct base64-encoded key"
echo "   2. The Cloud Build API is enabled in your GCP project"
echo "   3. The service account key hasn't expired"
