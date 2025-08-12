#!/bin/bash

# Test script to verify TCP registration functionality

SERVER_URL="https://tunnel-server-3w6u4kmniq-ue.a.run.app"

echo "Testing TCP registration API..."

# Test HTTP registration (backward compatibility)
echo "1. Testing HTTP registration (default):"
curl -s -X POST $SERVER_URL/register | jq '.'

echo -e "\n2. Testing HTTP registration (explicit):"
curl -s -X POST $SERVER_URL/register \
  -H "Content-Type: application/json" \
  -d '{"protocol":"http"}' | jq '.'

echo -e "\n3. Testing TCP registration:"
curl -s -X POST $SERVER_URL/register \
  -H "Content-Type: application/json" \
  -d '{"protocol":"tcp","port":22}' | jq '.'

echo -e "\n4. Testing TCP registration with different port:"
curl -s -X POST $SERVER_URL/register \
  -H "Content-Type: application/json" \
  -d '{"protocol":"tcp","port":5432}' | jq '.'

echo -e "\n5. Testing invalid TCP registration (missing port):"
curl -s -X POST $SERVER_URL/register \
  -H "Content-Type: application/json" \
  -d '{"protocol":"tcp"}' 

echo -e "\n6. Testing invalid protocol:"
curl -s -X POST $SERVER_URL/register \
  -H "Content-Type: application/json" \
  -d '{"protocol":"invalid"}' 

echo -e "\nTesting complete!"