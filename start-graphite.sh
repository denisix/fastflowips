#!/bin/bash

# Start Graphite test server with Docker
# Creates a complete Graphite stack with Carbon, Whisper, and Grafana

CONTAINER_NAME="graphite-test"
GRAPHITE_PORT="8080"
CARBON_PORT="2003"
GRAFANA_PORT="3000"

# Check if container is already running
if docker ps | grep -q $CONTAINER_NAME; then
    echo "Graphite container '$CONTAINER_NAME' is already running"
    echo "Graphite Web: http://localhost:$GRAPHITE_PORT"
    echo "Carbon receiver: localhost:$CARBON_PORT"
    echo "Grafana: http://localhost:$GRAFANA_PORT (admin/admin)"
    exit 0
fi

# Stop and remove existing container if it exists
if docker ps -a | grep -q $CONTAINER_NAME; then
    echo "Removing existing container..."
    docker stop $CONTAINER_NAME >/dev/null 2>&1
    docker rm $CONTAINER_NAME >/dev/null 2>&1
fi

echo "Starting Graphite test server..."

# Start Graphite container
docker run -d \
    --name $CONTAINER_NAME \
    --restart=unless-stopped \
    -p $GRAPHITE_PORT:80 \
    -p $CARBON_PORT:2003 \
    -p 2004:2004 \
    -p 2023:2023 \
    -p 2024:2024 \
    -p 8125:8125/udp \
    -p 8126:8126 \
    graphiteapp/graphite-statsd

# Wait for container to start
echo "Waiting for Graphite to start..."
sleep 10

# Check if container is running
if docker ps | grep -q $CONTAINER_NAME; then
    echo "✅ Graphite test server started successfully!"
    echo ""
    echo "📊 Graphite Web UI: http://localhost:$GRAPHITE_PORT"
    echo "📈 Carbon receiver: localhost:$CARBON_PORT"
    echo "🔧 Send metrics via TCP: echo \"metric.name value timestamp\" | nc localhost $CARBON_PORT"
    echo ""
    echo "To stop: docker stop $CONTAINER_NAME"
    echo "To remove: docker rm $CONTAINER_NAME"
else
    echo "❌ Failed to start Graphite container"
    docker logs $CONTAINER_NAME
    exit 1
fi