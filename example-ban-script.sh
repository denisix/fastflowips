#!/bin/bash

# Example ban/unban script for fastflowips
# This script demonstrates how to implement IP banning using iptables

ACTION="$1"
IP="$2"

if [ -z "$ACTION" ] || [ -z "$IP" ]; then
    echo "Usage: $0 <ban|unban> <ip_address>"
    exit 1
fi

# Validate IP address format
if ! echo "$IP" | grep -E "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" > /dev/null; then
    echo "Invalid IP address format: $IP"
    exit 1
fi

# Chain name for banned IPs
CHAIN_NAME="FASTFLOWIPS_BANNED"

# Ensure our custom chain exists
if ! iptables -L "$CHAIN_NAME" > /dev/null 2>&1; then
    iptables -N "$CHAIN_NAME"
    # Insert rule to jump to our chain at the beginning of INPUT
    iptables -I INPUT 1 -j "$CHAIN_NAME"
fi

case "$ACTION" in
    "ban")
        # Check if IP is already banned
        if iptables -C "$CHAIN_NAME" -s "$IP" -j DROP > /dev/null 2>&1; then
            echo "IP $IP is already banned"
        else
            # Ban the IP
            iptables -A "$CHAIN_NAME" -s "$IP" -j DROP
            echo "Banned IP: $IP"
            logger "fastflowips: Banned IP $IP due to threshold violation"
        fi
        ;;
    "unban")
        # Unban the IP
        if iptables -C "$CHAIN_NAME" -s "$IP" -j DROP > /dev/null 2>&1; then
            iptables -D "$CHAIN_NAME" -s "$IP" -j DROP
            echo "Unbanned IP: $IP"
            logger "fastflowips: Unbanned IP $IP"
        else
            echo "IP $IP was not banned"
        fi
        ;;
    *)
        echo "Unknown action: $ACTION"
        echo "Usage: $0 <ban|unban> <ip_address>"
        exit 1
        ;;
esac

exit 0