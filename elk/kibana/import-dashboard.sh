#!/bin/bash

# Galah Dashboard Auto-Import Script
# Uses curl to import the pre-configured dashboard

KIBANA_URL="http://kibana:5601"
KIBANA_USER="elastic"
KIBANA_PASS="${ELASTIC_PASSWORD:-galah123}"
DASHBOARD_FILE="/usr/share/kibana/dashboards/galah-security-dashboard.ndjson"

echo "🍯 Galah Honeypot Dashboard Auto-Import"
echo "=" * 50

# Wait for Kibana to be fully ready
echo "⏳ Waiting for Kibana to be ready..."
max_retries=30
for i in $(seq 1 $max_retries); do
    if curl -s -u "$KIBANA_USER:$KIBANA_PASS" "$KIBANA_URL/api/status" | grep -q '"level":"available"'; then
        echo "✅ Kibana is ready!"
        break
    fi
    echo "   Attempt $i/$max_retries: Waiting 10 seconds..."
    sleep 10
    if [ $i -eq $max_retries ]; then
        echo "❌ Kibana failed to become ready"
        exit 1
    fi
done

# Additional delay to ensure full readiness
sleep 5

# Create index pattern
echo "📊 Creating index pattern..."
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
  }' > /tmp/index_response.json 2>/dev/null

index_status=$?
if [ $index_status -eq 0 ]; then
    echo "✅ Index pattern created/exists"
else
    echo "⚠️  Index pattern creation had issues, but continuing..."
fi

# Import dashboard
echo "📈 Importing dashboard..."
if [ ! -f "$DASHBOARD_FILE" ]; then
    echo "❌ Dashboard file not found: $DASHBOARD_FILE"
    exit 1
fi

curl -X POST \
  -u "$KIBANA_USER:$KIBANA_PASS" \
  -H "kbn-xsrf: true" \
  "$KIBANA_URL/api/saved_objects/_import?overwrite=true" \
  -F "file=@$DASHBOARD_FILE" > /tmp/import_response.json 2>/dev/null

import_status=$?
if [ $import_status -eq 0 ]; then
    import_result=$(cat /tmp/import_response.json)
    if echo "$import_result" | grep -q '"success":true'; then
        echo "✅ Dashboard imported successfully!"
        echo "🌐 Access dashboard at: $KIBANA_URL/app/dashboards#/view/galah-security-dashboard"
        echo "🔑 Login: $KIBANA_USER / $KIBANA_PASS"
    else
        echo "⚠️ Dashboard import completed but with issues:"
        cat /tmp/import_response.json
    fi
else
    echo "❌ Dashboard import failed"
    cat /tmp/import_response.json
    exit 1
fi

echo "🎯 Dashboard setup complete!"