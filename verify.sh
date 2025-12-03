#!/bin/bash
# Zaply Complete Verification Script
# Checks all components for errors and debugging issues

echo "=================================================="
echo "ZAPLY VERIFICATION & DEBUGGING SCRIPT"
echo "=================================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counter for issues
ERRORS=0
WARNINGS=0
PASSED=0

# Function to print status
print_status() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✅ PASS${NC}: $2"
        ((PASSED++))
    elif [ $1 -eq 1 ]; then
        echo -e "${YELLOW}⚠️  WARN${NC}: $2"
        ((WARNINGS++))
    else
        echo -e "${RED}❌ FAIL${NC}: $2"
        ((ERRORS++))
    fi
}

echo -e "${BLUE}1. CHECKING FILE STRUCTURE${NC}"
[ -f "docker-compose.yml" ] && print_status 0 "docker-compose.yml exists" || print_status 2 "docker-compose.yml missing"
[ -f "nginx.conf" ] && print_status 0 "nginx.conf exists" || print_status 2 "nginx.conf missing"
[ -f ".env.example" ] && print_status 0 ".env.example exists" || print_status 2 ".env.example missing"
[ -f "backend/main.py" ] && print_status 0 "backend/main.py exists" || print_status 2 "backend/main.py missing"
[ -f "frontend/app.py" ] && print_status 0 "frontend/app.py exists" || print_status 2 "frontend/app.py missing"
echo ""

echo -e "${BLUE}2. CHECKING DOCUMENTATION${NC}"
[ -f "README.md" ] && print_status 0 "README.md exists" || print_status 1 "README.md missing"
[ -f "NGINX_SETUP.md" ] && print_status 0 "NGINX_SETUP.md exists" || print_status 1 "NGINX_SETUP.md missing"
[ -f "DEPLOYMENT.md" ] && print_status 0 "DEPLOYMENT.md exists" || print_status 1 "DEPLOYMENT.md missing"
[ -f "NGINX_SUMMARY.md" ] && print_status 0 "NGINX_SUMMARY.md exists" || print_status 1 "NGINX_SUMMARY.md missing"
echo ""

echo -e "${BLUE}3. CHECKING CONFIGURATION FILES${NC}"
if grep -q "upstream backend_service" nginx.conf; then
    print_status 0 "nginx.conf has upstream backend_service"
else
    print_status 2 "nginx.conf missing upstream backend_service"
fi

if grep -q "upstream frontend_service" nginx.conf; then
    print_status 0 "nginx.conf has upstream frontend_service"
else
    print_status 2 "nginx.conf missing upstream frontend_service"
fi

if grep -q "listen 80" nginx.conf; then
    print_status 0 "nginx.conf configured for HTTP (port 80)"
else
    print_status 2 "nginx.conf not configured for port 80"
fi

if grep -q "client_max_body_size 40G" nginx.conf; then
    print_status 0 "nginx.conf supports 40GB file uploads"
else
    print_status 2 "nginx.conf file upload size not configured"
fi
echo ""

echo -e "${BLUE}4. CHECKING DOCKER-COMPOSE${NC}"
if grep -q "nginx:" docker-compose.yml; then
    print_status 0 "docker-compose.yml has nginx service"
else
    print_status 2 "docker-compose.yml missing nginx service"
fi

if grep -q "backend:" docker-compose.yml; then
    print_status 0 "docker-compose.yml has backend service"
else
    print_status 2 "docker-compose.yml missing backend service"
fi

if grep -q "frontend:" docker-compose.yml; then
    print_status 0 "docker-compose.yml has frontend service"
else
    print_status 2 "docker-compose.yml missing frontend service"
fi

if grep -q "mongodb:" docker-compose.yml; then
    print_status 0 "docker-compose.yml has mongodb service"
else
    print_status 2 "docker-compose.yml missing mongodb service"
fi

if grep -q "hypersend_network:" docker-compose.yml; then
    print_status 0 "docker-compose.yml has hypersend_network"
else
    print_status 2 "docker-compose.yml missing network"
fi
echo ""

echo -e "${BLUE}5. CHECKING ENVIRONMENT VARIABLES${NC}"
if grep -q "MONGO_USER" .env.example; then
    print_status 0 ".env.example has MONGO_USER"
else
    print_status 1 ".env.example missing MONGO_USER"
fi

if grep -q "SECRET_KEY" .env.example; then
    print_status 0 ".env.example has SECRET_KEY"
else
    print_status 2 ".env.example missing SECRET_KEY"
fi

if grep -q "VPS_IP" .env.example; then
    print_status 0 ".env.example has VPS_IP"
else
    print_status 1 ".env.example missing VPS_IP"
fi

if grep -q "API_BASE_URL" .env.example; then
    print_status 0 ".env.example has API_BASE_URL"
else
    print_status 1 ".env.example missing API_BASE_URL"
fi
echo ""

echo -e "${BLUE}6. CHECKING BACKEND CODE${NC}"
if grep -q "class ZaplyApp" frontend/app.py; then
    print_status 0 "Frontend has ZaplyApp class"
else
    print_status 2 "Frontend missing ZaplyApp class"
fi

if grep -q "ft.app(target=main, name=\"Zaply\")" frontend/app.py; then
    print_status 0 "Frontend app name set to 'Zaply'"
else
    print_status 1 "Frontend app name not set properly"
fi

if grep -q "page.bgcolor = self.bg_dark" frontend/app.py; then
    print_status 0 "Frontend sets page background color"
else
    print_status 1 "Frontend may have white screen issue"
fi
echo ""

echo -e "${BLUE}7. CHECKING SECURITY${NC}"
if grep -q 'MONGO_PASSWORD:-changeme' docker-compose.yml; then
    print_status 1 "MongoDB default password used (changeme) - change before production"
else
    print_status 0 "MongoDB password configured"
fi

if grep -q 'DEBUG:-False' docker-compose.yml; then
    print_status 0 "DEBUG mode disabled in production"
else
    print_status 1 "DEBUG mode configuration issue"
fi

if grep -q 'SECRET_KEY' .env.example && ! grep -q 'your-secret' .env.example; then
    print_status 0 "SECRET_KEY configured in .env.example"
else
    print_status 1 "SECRET_KEY may need update"
fi
echo ""

echo -e "${BLUE}8. CHECKING GIT STATUS${NC}"
if git rev-parse --git-dir > /dev/null 2>&1; then
    print_status 0 "Git repository initialized"
    
    # Check for uncommitted changes
    if [ -z "$(git status --porcelain)" ]; then
        print_status 0 "All files committed"
    else
        print_status 1 "Uncommitted changes exist"
    fi
    
    # Check remote
    if git remote get-url origin > /dev/null 2>&1; then
        print_status 0 "Git remote configured"
    else
        print_status 1 "Git remote not configured"
    fi
else
    print_status 1 "Not a git repository"
fi
echo ""

echo -e "${BLUE}9. CHECKING API ENDPOINTS${NC}"
if grep -q "/api/v1" backend/main.py; then
    print_status 0 "API endpoints configured with /api/v1 prefix"
else
    print_status 2 "API endpoints not properly configured"
fi

if grep -q "@app.get(\"/health\")" backend/main.py; then
    print_status 0 "Health check endpoint exists"
else
    print_status 1 "Health check endpoint missing"
fi
echo ""

echo -e "${BLUE}10. CHECKING REQUIRED PORTS${NC}"
grep -q "80:80" docker-compose.yml && print_status 0 "Port 80 (HTTP) configured" || print_status 1 "Port 80 not mapped"
grep -q "443:443" docker-compose.yml && print_status 0 "Port 443 (HTTPS) configured" || print_status 1 "Port 443 not mapped"
grep -q "8000:8000" docker-compose.yml && print_status 0 "Port 8000 (Backend) internal" || print_status 1 "Backend port issue"
grep -q "8550:8550" docker-compose.yml && print_status 0 "Port 8550 (Frontend) internal" || print_status 1 "Frontend port issue"
grep -q "27017:27017" docker-compose.yml && print_status 0 "Port 27017 (MongoDB) internal" || print_status 1 "MongoDB port issue"
echo ""

echo "=================================================="
echo -e "${BLUE}VERIFICATION SUMMARY${NC}"
echo "=================================================="
echo -e "${GREEN}✅ Passed: $PASSED${NC}"
echo -e "${YELLOW}⚠️  Warnings: $WARNINGS${NC}"
echo -e "${RED}❌ Errors: $ERRORS${NC}"
echo ""

if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}🎉 ALL CHECKS PASSED - READY FOR DEPLOYMENT!${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Deploy to VPS: docker-compose up -d"
    echo "2. Check status: docker-compose ps"
    echo "3. Test health: curl http://139.59.82.105/health"
    echo "4. View logs: docker logs -f hypersend_nginx"
    exit 0
else
    echo -e "${RED}⚠️  PLEASE FIX ERRORS BEFORE DEPLOYMENT${NC}"
    exit 1
fi
