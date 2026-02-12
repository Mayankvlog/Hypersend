#!/bin/bash

# =============================================================================
# Hypersend VPS Deployment Script
# =============================================================================
# This script deploys Hypersend to your VPS using Docker Hub images
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="hypersend"
BACKUP_DIR="/opt/backups/hypersend"
LOG_FILE="/var/log/hypersend-deploy.log"

# Functions
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" | tee -a "$LOG_FILE"
    exit 1
}

success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}" | tee -a "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}" | tee -a "$LOG_FILE"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        error "This script should not be run as root. Run as a regular user with sudo privileges."
    fi
}

# Check system requirements
check_requirements() {
    log "Checking system requirements..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        error "Docker is not installed. Please install Docker first."
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        error "Docker Compose is not installed. Please install Docker Compose first."
    fi
    
    # Check available memory
    AVAILABLE_MEMORY=$(free -m | awk 'NR==2{printf "%.0f", $7}')
    if [[ $AVAILABLE_MEMORY -lt 2048 ]]; then
        warning "System has less than 2GB of available memory. Performance may be affected."
    fi
    
    # Check disk space
    AVAILABLE_DISK=$(df -h / | awk 'NR==2{print $4}' | sed 's/G//')
    if [[ $AVAILABLE_DISK -lt 10 ]]; then
        error "Insufficient disk space. At least 10GB required."
    fi
    
    success "System requirements check passed"
}

# Setup directories
setup_directories() {
    log "Setting up directories..."
    
    sudo mkdir -p "$BACKUP_DIR"
    sudo mkdir -p ./data/uploads
    sudo mkdir -p ./logs
    sudo mkdir -p ./ssl
    
    sudo chown -R $USER:$USER ./data
    sudo chown -R $USER:$USER ./logs
    sudo chown -R $USER:$USER ./ssl
    sudo chown -R $USER:$USER "$BACKUP_DIR"
    
    success "Directories created and permissions set"
}

# Backup current deployment
backup_current() {
    if docker-compose ps | grep -q "Up"; then
        log "Backing up current deployment..."
        
        BACKUP_NAME="$PROJECT_NAME-$(date +%Y%m%d-%H%M%S)"
        sudo mkdir -p "$BACKUP_DIR/$BACKUP_NAME"
        
        # Backup volumes
        docker run --rm -v hypersend_redis_data:/data -v "$BACKUP_DIR/$BACKUP_NAME":/backup alpine tar czf /backup/redis_data.tar.gz -C /data .
        docker run --rm -v hypersend_nginx_cache:/data -v "$BACKUP_DIR/$BACKUP_NAME":/backup alpine tar czf /backup/nginx_cache.tar.gz -C /data .
        docker run --rm -v hypersend_uploads_data:/data -v "$BACKUP_DIR/$BACKUP_NAME":/backup alpine tar czf /backup/uploads_data.tar.gz -C /data .
        
        # Backup configuration
        cp -r ./config "$BACKUP_DIR/$BACKUP_NAME/" 2>/dev/null || true
        cp .env* "$BACKUP_DIR/$BACKUP_NAME/" 2>/dev/null || true
        
        success "Backup created: $BACKUP_DIR/$BACKUP_NAME"
    else
        log "No running deployment found, skipping backup"
    fi
}

# Pull latest images
pull_images() {
    log "Pulling latest Docker Hub images..."
    
    docker-compose pull
    
    success "Images pulled successfully"
}

# Stop existing services
stop_services() {
    log "Stopping existing services..."
    
    docker-compose down || true
    
    success "Services stopped"
}

# Start services
start_services() {
    log "Starting services..."
    
    # Start core services first
    docker-compose up -d redis
    
    # Wait for Redis to be healthy
    log "Waiting for Redis to be healthy..."
    timeout 60 bash -c 'until docker-compose exec redis redis-cli ping | grep -q PONG; do sleep 2; done'
    
    # Start backend
    docker-compose up -d backend
    
    # Wait for backend to be healthy
    log "Waiting for backend to be healthy..."
    timeout 180 bash -c 'until curl -f http://localhost:8000/health; do sleep 5; done'
    
    # Start remaining services
    docker-compose up -d
    
    success "All services started"
}

# Health check
health_check() {
    log "Performing health checks..."
    
    # Check backend
    if curl -f http://localhost:8000/health > /dev/null 2>&1; then
        success "Backend health check passed"
    else
        error "Backend health check failed"
    fi
    
    # Check frontend
    if curl -f http://localhost:3000/health > /dev/null 2>&1; then
        success "Frontend health check passed"
    else
        error "Frontend health check failed"
    fi
    
    # Check Redis
    if docker-compose exec redis redis-cli ping | grep -q PONG; then
        success "Redis health check passed"
    else
        error "Redis health check failed"
    fi
    
    # Check Nginx
    if curl -f http://localhost/health > /dev/null 2>&1; then
        success "Nginx health check passed"
    else
        error "Nginx health check failed"
    fi
}

# Setup SSL certificates
setup_ssl() {
    log "Setting up SSL certificates..."
    
    if [[ ! -f "./ssl/cert.pem" ]] || [[ ! -f "./ssl/key.pem" ]]; then
        log "Generating self-signed SSL certificates..."
        
        openssl req -x509 -newkey rsa:4096 -keyout ./ssl/key.pem -out ./ssl/cert.pem -days 365 -nodes \
            -subj "/C=US/ST=State/L=City/O=Hypersend/CN=${DOMAIN_NAME:-localhost}"
        
        success "Self-signed SSL certificates generated"
        warning "Remember to replace with proper SSL certificates for production"
    else
        log "SSL certificates already exist"
    fi
}

# Cleanup old images and containers
cleanup() {
    log "Cleaning up old Docker resources..."
    
    docker image prune -f
    docker container prune -f
    docker volume prune -f
    
    success "Cleanup completed"
}

# Show status
show_status() {
    log "Deployment status:"
    echo
    docker-compose ps
    echo
    log "Service URLs:"
    echo "  Frontend: https://${DOMAIN_NAME:-localhost}"
    echo "  Backend API: https://${DOMAIN_NAME:-localhost}/api/v1"
    echo "  Health Check: https://${DOMAIN_NAME:-localhost}/health"
    echo
    log "Logs: docker-compose logs -f [service-name]"
}

# Main deployment function
deploy() {
    log "Starting Hypersend deployment..."
    
    check_root
    check_requirements
    setup_directories
    setup_ssl
    backup_current
    pull_images
    stop_services
    start_services
    health_check
    cleanup
    show_status
    
    success "Hypersend deployment completed successfully!"
}

# Rollback function
rollback() {
    log "Rolling back to previous deployment..."
    
    if [[ -z "$1" ]]; then
        error "Please specify backup directory: ./deploy-vps.sh rollback backup-name"
    fi
    
    BACKUP_PATH="$BACKUP_DIR/$1"
    
    if [[ ! -d "$BACKUP_PATH" ]]; then
        error "Backup directory not found: $BACKUP_PATH"
    fi
    
    stop_services
    
    # Restore volumes
    docker run --rm -v hypersend_redis_data:/data -v "$BACKUP_PATH":/backup alpine tar xzf /backup/redis_data.tar.gz -C /data
    docker run --rm -v hypersend_nginx_cache:/data -v "$BACKUP_PATH":/backup alpine tar xzf /backup/nginx_cache.tar.gz -C /data
    docker run --rm -v hypersend_uploads_data:/data -v "$BACKUP_PATH":/backup alpine tar xzf /backup/uploads_data.tar.gz -C /data
    
    # Restore configuration
    cp "$BACKUP_PATH"/.env* ./ 2>/dev/null || true
    
    start_services
    health_check
    
    success "Rollback completed successfully!"
}

# Show usage
usage() {
    echo "Hypersend VPS Deployment Script"
    echo
    echo "Usage:"
    echo "  $0 deploy              - Deploy Hypersend"
    echo "  $0 rollback <backup>   - Rollback to specific backup"
    echo "  $0 status              - Show deployment status"
    echo "  $0 logs [service]      - Show logs for all or specific service"
    echo "  $0 backup              - Create manual backup"
    echo "  $0 help                - Show this help"
    echo
    echo "Examples:"
    echo "  $0 deploy"
    echo "  $0 rollback hypersend-20231215-143022"
    echo "  $0 logs backend"
    echo "  $0 status"
}

# Main script logic
case "${1:-deploy}" in
    "deploy")
        deploy
        ;;
    "rollback")
        rollback "$2"
        ;;
    "status")
        show_status
        ;;
    "logs")
        if [[ -n "$2" ]]; then
            docker-compose logs -f "$2"
        else
            docker-compose logs -f
        fi
        ;;
    "backup")
        backup_current
        ;;
    "help"|"-h"|"--help")
        usage
        ;;
    *)
        error "Unknown command: $1. Use '$0 help' for usage information."
        ;;
esac
