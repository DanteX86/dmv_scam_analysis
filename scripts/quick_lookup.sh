#!/bin/bash

# Quick Lookup Script for Scam Analysis
# Usage: ./quick_lookup.sh [phone|email|username] [value]

TYPE=$1
VALUE=$2

if [ -z "$TYPE" ] || [ -z "$VALUE" ]; then
    echo "Usage: $0 [phone|email|username] [value]"
    echo "Examples:"
    echo "  $0 phone +27618264263"
    echo "  $0 email suspicious@example.com"
    echo "  $0 username scammer123"
    exit 1
fi

case $TYPE in
    phone)
        echo "=== PHONE NUMBER ANALYSIS: $VALUE ==="
        echo "Running PhoneInfoGA scan..."
        phoneinfoga scan -n "$VALUE"
        ;;
    email)
        echo "=== EMAIL ANALYSIS: $VALUE ==="
        echo "Running Holehe scan..."
        holehe "$VALUE"
        ;;
    username)
        echo "=== USERNAME ANALYSIS: $VALUE ==="
        echo "Running Sherlock scan..."
        sherlock "$VALUE"
        ;;
    *)
        echo "Invalid type. Use: phone, email, or username"
        exit 1
        ;;
esac
