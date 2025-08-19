#!/bin/bash
set -e

# Configuration
PROJECT_ID="contact-center-insights-poc"
SERVICE_ACCOUNT_NAME="gitlab-ci-deployment"
SERVICE_ACCOUNT_EMAIL="${SERVICE_ACCOUNT_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
KEY_FILE="gitlab-ci-service-account-key.json"

echo "Setting up GCP Service Account for GitLab CI/CD..."

# Check if service account already exists
if gcloud iam service-accounts describe $SERVICE_ACCOUNT_EMAIL --project=$PROJECT_ID >/dev/null 2>&1; then
    echo "Service account already exists: $SERVICE_ACCOUNT_EMAIL"
else
    # Create service account
    echo "Creating service account: $SERVICE_ACCOUNT_EMAIL"
    gcloud iam service-accounts create $SERVICE_ACCOUNT_NAME \
        --project=$PROJECT_ID \
        --description="Service account for GitLab CI/CD deployments" \
        --display-name="GitLab CI Deployment"
fi

# Wait a moment for service account to propagate
sleep 2

# Assign minimum required roles
echo "Assigning IAM roles..."

# Cloud Build Editor - needed to submit builds
echo "  - Cloud Build Editor"
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SERVICE_ACCOUNT_EMAIL" \
    --role="roles/cloudbuild.builds.editor" \
    --quiet

# Cloud Run Admin - needed to deploy and update services  
echo "  - Cloud Run Admin"
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SERVICE_ACCOUNT_EMAIL" \
    --role="roles/run.admin" \
    --quiet

# Storage Object Admin - needed for build artifacts and container images
echo "  - Storage Object Admin"
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SERVICE_ACCOUNT_EMAIL" \
    --role="roles/storage.objectAdmin" \
    --quiet

# Container Registry access - storage.objectAdmin should be sufficient for gcr.io

# Service Account User - needed to deploy Cloud Run services with service accounts
echo "  - Service Account User"
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SERVICE_ACCOUNT_EMAIL" \
    --role="roles/iam.serviceAccountUser" \
    --quiet

# Generate and download service account key
echo "Generating service account key..."
gcloud iam service-accounts keys create $KEY_FILE \
    --iam-account=$SERVICE_ACCOUNT_EMAIL \
    --project=$PROJECT_ID

echo ""
echo "✅ Service account setup complete!"
echo ""
echo "📋 Next steps for GitHub configuration:"
echo "1. In your GitHub repository, go to Settings > Secrets and variables > Actions"
echo "2. Add the following repository secret:"
echo ""
echo "   Secret Name: GCP_SERVICE_ACCOUNT_KEY"
echo "   Value: (paste the base64 encoded content below)"
echo ""
echo "📄 Base64 encoded service account key (copy this to GitHub Secrets):"
echo "─────────────────────────────────────────────────────────────"
base64 -i $KEY_FILE
echo "─────────────────────────────────────────────────────────────"
echo ""
echo "🔐 Security note: The service account key file '$KEY_FILE' has been created locally."
echo "    After copying to GitHub Secrets, you should securely delete this file:"
echo "    rm $KEY_FILE"
echo ""
echo "🔍 To verify permissions were set correctly:"
echo "    gcloud projects get-iam-policy $PROJECT_ID --flatten=\"bindings[].members\" --filter=\"bindings.members:$SERVICE_ACCOUNT_EMAIL\""