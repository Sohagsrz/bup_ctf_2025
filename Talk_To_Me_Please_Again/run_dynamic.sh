#!/bin/bash
# Script to run dynamic analysis

echo "=========================================="
echo "Dynamic Analysis - Talk To Me Please Again"
echo "=========================================="
echo ""

# Check if Docker is available
if command -v docker &> /dev/null; then
    echo "✅ Docker found"
    echo "Building Docker image..."
    docker build -t ttmpa-test .
    
    echo ""
    echo "Running tests in Docker..."
    docker run --rm ttmpa-test
    
elif command -v qemu-x86_64 &> /dev/null; then
    echo "✅ QEMU found"
    echo "Running binary with QEMU..."
    echo ""
    echo "Note: You'll need to test inputs manually or modify test_dynamic.py"
    echo "to use qemu-x86_64 instead of direct execution"
    qemu-x86_64 -L /usr/x86_64-linux-gnu TTMPA/ttmpa.ks
    
else
    echo "❌ Neither Docker nor QEMU found"
    echo ""
    echo "Options:"
    echo "1. Install Docker: https://docs.docker.com/get-docker/"
    echo "2. Install QEMU: brew install qemu (on macOS)"
    echo "3. Use an online Linux environment"
    echo ""
    echo "Or try running the binary directly if you're on Linux:"
    echo "  python3 test_dynamic.py"
fi


