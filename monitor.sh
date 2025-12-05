#!/bin/bash
# Service startup and monitoring script for Hypersend

# Auto-restart services if they crash
while true; do
    # Check if backend is running
    if ! docker-compose exec backend curl -sf http://localhost:8000/health > /dev/null 2>&1; then
        echo "[$(date)] Backend health check failed, restarting..."
        docker-compose restart backend
    fi
    
    # Check if mongodb is running
    if ! docker-compose exec mongodb mongosh --eval "db.adminCommand('ping')" > /dev/null 2>&1; then
        echo "[$(date)] MongoDB health check failed, restarting..."
        docker-compose restart mongodb
    fi
    
    # Check if nginx is running
    if ! docker-compose exec nginx curl -sf http://localhost/health > /dev/null 2>&1; then
        echo "[$(date)] Nginx health check failed, restarting..."
        docker-compose restart nginx
    fi
    
    # Sleep before next check
    sleep 60
done
