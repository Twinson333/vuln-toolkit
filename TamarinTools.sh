#!/bin/bash

figlet "CyberTamarin"
echo "======================================"
echo "   Simple Vulnerability Scanner Menu"
echo "======================================"
echo "Select scan type:"
echo "1) XSS"
echo "2) CSRF"
echo "3) CRLF"
echo "4) All"
read -p "Enter your choice (1-4): " CHOICE

# Get target input
read -p "Enter URL or path to file containing URLs: " INPUT

# Determine URL flag
if [[ -f "$INPUT" ]]; then
    URL_FLAG="-l $INPUT"
else
    URL_FLAG="-u $INPUT"
fi

# Optional payload inputs
if [[ "$CHOICE" == "1" || "$CHOICE" == "4" ]]; then
    read -p "Enter path to XSS payload file: " XSS_PAYLOADS
fi

if [[ "$CHOICE" == "3" || "$CHOICE" == "4" ]]; then
    read -p "Enter path to CRLF payload file: " CRLF_PAYLOADS
fi

# Output files
XSS_OUT="xss_results.txt"
CSRF_OUT="csrf_results.txt"
CRLF_OUT="crlf_results.txt"

echo -e "\n============================="
echo "  Starting Scan..."
echo "============================="

# XSS Scan
if [[ "$CHOICE" == "1" || "$CHOICE" == "4" ]]; then
    echo -e "\n Running XSS Scan..."
    python3 xss_detector.py $URL_FLAG -p "$XSS_PAYLOADS" -o "$XSS_OUT"
fi

# CSRF Scan
if [[ "$CHOICE" == "2" || "$CHOICE" == "4" ]]; then
    echo -e "\n Running CSRF Scan..."
    python3 csrf_detector.py $URL_FLAG -o "$CSRF_OUT"
fi

# CRLF Scan
if [[ "$CHOICE" == "3" || "$CHOICE" == "4" ]]; then
    echo -e "\n Running CRLF Scan..."
    python3 crlf_detector.py $URL_FLAG -p "$CRLF_PAYLOADS" -o "$CRLF_OUT"
fi

echo -e "\n Scan Complete! Results:"
[[ "$CHOICE" == "1" || "$CHOICE" == "4" ]] && echo "   - XSS  => $XSS_OUT"
[[ "$CHOICE" == "2" || "$CHOICE" == "4" ]] && echo "   - CSRF => $CSRF_OUT"
[[ "$CHOICE" == "3" || "$CHOICE" == "4" ]] && echo "   - CRLF => $CRLF_OUT"
