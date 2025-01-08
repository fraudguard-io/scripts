#!/bin/bash

# Configuration
USERNAME="" # Replace with your FraudGuard.io API key username
PASSWORD="" # Replace with your FraudGuard.io API key password
API_URL="https://api.fraudguard.io/raw-lists-by-threat"
LOG_FILE="ufw_block_by_threat.log"
THREAT_TYPE="honeypot_tracker" # Replace with the desired threat type
OFFSET=0
LIMIT=50 # Number of IPs per request (set to 1000 for production)
MAX_RESULTS=50 # Hard limit for total IPs (set 0 to disable for production)
SLEEP_INTERVAL=2 # Sleep duration (in seconds) between requests

# Fetch and apply the IP list
echo "Fetching IPs classified as $THREAT_TYPE from FraudGuard.io..."
while true; do
    echo "Fetching from offset $OFFSET..."
    RESPONSE=$(curl -s -u "$USERNAME:$PASSWORD" -D - "${API_URL}/${THREAT_TYPE}?offset=${OFFSET}&limit=${LIMIT}&cidr=false&ipv6=false" -o /tmp/threat_ips.json)
    
    # Extract HTTP headers and body
    HTTP_STATUS=$(echo "$RESPONSE" | grep -oE 'HTTP/[0-9\.]+ [0-9]+' | awk '{print $2}')
    TOTAL_COUNT=$(echo "$RESPONSE" | grep -i 'X-Total-Count:' | awk '{print $2}' | tr -d '\r')

    # Check for HTTP errors
    if [[ "$HTTP_STATUS" -ne 200 ]]; then
        echo "Error: Failed to fetch IPs. HTTP Status: $HTTP_STATUS" | tee -a "$LOG_FILE"
        exit 1
    fi

    # Parse the response body
    IP_LIST=$(cat /tmp/threat_ips.json)
    IP_COUNT=$(echo "$IP_LIST" | jq '. | length')

    # Break if no more IPs
    if [[ "$IP_COUNT" -eq 0 ]]; then
        echo "No more IPs to process. Sync complete!"
        break
    fi

    # Apply each IP to UFW
    echo "Blocking $IP_COUNT IPs with UFW..."
    for IP in $(echo "$IP_LIST" | jq -r '.[]'); do
        # Check if IP is already blocked
        ufw status | grep -q "$IP"
        if [[ $? -ne 0 ]]; then
            ufw deny from "$IP" comment "Blocked by FraudGuard.io (Threat: $THREAT_TYPE)"
            echo "Blocked: $IP" | tee -a "$LOG_FILE"
        else
            echo "Already blocked: $IP" | tee -a "$LOG_FILE"
        fi
    done

    # Update offset for pagination
    OFFSET=$((OFFSET + LIMIT))

    # Respect the total count and hard limit
    if [[ "$MAX_RESULTS" -gt 0 && "$OFFSET" -ge "$MAX_RESULTS" ]]; then
        echo "Reached hard limit of $MAX_RESULTS IPs. Sync complete!"
        break
    fi
    if [[ -n "$TOTAL_COUNT" && "$OFFSET" -ge "$TOTAL_COUNT" ]]; then
        echo "Reached total count of $TOTAL_COUNT IPs. Sync complete!"
        break
    fi

    # Sleep to avoid overloading the API
    echo "Sleeping for $SLEEP_INTERVAL seconds to prevent API overload..."
    sleep $SLEEP_INTERVAL
done

# Reload UFW to apply changes
echo "Reloading UFW..."
ufw reload

echo "UFW threat-based blocking complete!" | tee -a "$LOG_FILE"