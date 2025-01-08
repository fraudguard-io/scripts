#!/bin/bash

# Configuration
USERNAME="" # Replace with your FraudGuard.io username
PASSWORD="" # Replace with your FraudGuard.io password
API_URL="https://api.fraudguard.io/blacklist"
LOG_FILE="ufw_sync_blacklist.log"
OFFSET=0
PAGE_LIMIT=1000

# Fetch and apply the blacklist
echo "Fetching custom blacklist from FraudGuard.io..."
while true; do
    echo "Fetching blacklist from offset $OFFSET..."
    RESPONSE=$(curl -s -u "$USERNAME:$PASSWORD" -w "%{http_code}" -o /tmp/blacklist.json "${API_URL}/${OFFSET}")

    # Extract the HTTP status code from the response
    HTTP_STATUS=$(tail -n1 <<< "$RESPONSE")
    
    # Validate the HTTP response
    if [[ "$HTTP_STATUS" -ne 200 ]]; then
        echo "Error: Failed to fetch blacklist from FraudGuard.io. HTTP Status: $HTTP_STATUS" | tee -a "$LOG_FILE"
        exit 1
    fi

    # Parse the JSON response
    BLACKLIST=$(cat /tmp/blacklist.json)
    IP_COUNT=$(echo "$BLACKLIST" | jq '. | length')

    # If no more IPs are returned, break the loop
    if [[ "$IP_COUNT" -eq 0 ]]; then
        echo "No more IPs to process. Sync complete!"
        break
    fi

    # Apply each IP or subnet to UFW
    echo "Applying $IP_COUNT IPs to UFW..."
    for IP in $(echo "$BLACKLIST" | jq -r '.[]'); do
        # Check if the IP or subnet is already blocked
        ufw status | grep -q "$IP"
        if [[ $? -ne 0 ]]; then
            ufw deny from "$IP" comment "Blocked by FraudGuard.io Blacklist API"
            echo "Blocked: $IP" | tee -a "$LOG_FILE"
        else
            echo "Already blocked: $IP" | tee -a "$LOG_FILE"
        fi
    done

    # Increment the offset for the next page
    OFFSET=$((OFFSET + PAGE_LIMIT))
done

# Reload UFW to apply changes
echo "Reloading UFW..."
ufw reload

echo "UFW blacklist sync complete!" | tee -a "$LOG_FILE"