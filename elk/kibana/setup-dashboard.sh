#!/bin/bash

# Galah Honeypot Dashboard Setup Script
# This script automatically imports the pre-configured dashboard into Kibana

KIBANA_URL="http://localhost:5601"
KIBANA_USER="elastic"
KIBANA_PASS="galah123"
DASHBOARD_FILE="/usr/share/kibana/dashboards/galah-security-dashboard.ndjson"

echo "🍯 Setting up Galah Honeypot Dashboard..."

# Wait for Kibana to be ready
echo "⏳ Waiting for Kibana to be ready..."
until curl -s -u "$KIBANA_USER:$KIBANA_PASS" "$KIBANA_URL/api/status" | grep -q "\"state\":\"green\""; do
  echo "   Kibana not ready yet, waiting 5 seconds..."
  sleep 5
done

echo "✅ Kibana is ready!"

# Import the dashboard
echo "📊 Importing Galah Security Dashboard..."
curl -X POST \
  -u "$KIBANA_USER:$KIBANA_PASS" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  "$KIBANA_URL/api/saved_objects/_import" \
  -F "file=@$DASHBOARD_FILE"

if [ $? -eq 0 ]; then
    echo "✅ Dashboard imported successfully!"
    echo "🌐 Access your dashboard at: $KIBANA_URL/app/dashboards#/view/galah-security-dashboard"
    echo "🔑 Login: $KIBANA_USER / $KIBANA_PASS"
else
    echo "❌ Dashboard import failed"
fi

echo "📈 Setting up index pattern..."
curl -X POST \
  -u "$KIBANA_USER:$KIBANA_PASS" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  "$KIBANA_URL/api/saved_objects/index-pattern/galah-events-*" \
  -d '{
    "attributes": {
      "title": "galah-events-*",
      "timeFieldName": "@timestamp"
    }
  }' > /dev/null 2>&1

echo "🎯 Dashboard setup complete!"