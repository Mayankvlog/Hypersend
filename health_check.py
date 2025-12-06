#!/usr/bin/env python3
"""
Hypersend Health Check & Monitoring Script
Monitors all services and provides diagnostic information
"""

import subprocess
import sys
import time
import requests
from datetime import datetime
from pathlib import Path

# Configuration
VPS_IP = "139.59.82.105"
SERVICES = {
    "backend": f"http://{VPS_IP}:8000/health",
    "nginx": f"http://{VPS_IP}:8080/health",
    "mongodb": "internal",
}

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_header(title):
    """Print formatted header"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*50}")
    print(f"{title}")
    print(f"{'='*50}{Colors.RESET}\n")

def print_status(service, status, message=""):
    """Print service status"""
    if status == "OK":
        icon = f"{Colors.GREEN}✅{Colors.RESET}"
    elif status == "WARNING":
        icon = f"{Colors.YELLOW}⚠️ {Colors.RESET}"
    else:
        icon = f"{Colors.RED}❌{Colors.RESET}"
    
    print(f"{icon} {service:<15} {status:<10} {message}")

def check_docker_services():
    """Check if Docker services are running"""
    print_header("Docker Services Status")
    
    try:
        output = subprocess.check_output(
            ["docker-compose", "ps", "--format", "table {{.Service}}\t{{.Status}}"],
            stderr=subprocess.DEVNULL,
            text=True
        )
        
        services = {}
        for line in output.strip().split('\n')[1:]:  # Skip header
            if line.strip():
                parts = line.split()
                if len(parts) >= 2:
                    service = parts[0]
                    status = ' '.join(parts[1:])
                    services[service] = status
                    is_running = "Up" in status
                    print_status(service, "Running" if is_running else "Stopped", status)
        
        return services
    except Exception as e:
        print_status("Docker", "ERROR", str(e))
        return {}

def check_backend_health():
    """Check backend API health"""
    print_header("Backend API Health")
    
    try:
        response = requests.get(SERVICES["backend"], timeout=5)
        if response.status_code == 200:
            print_status("Backend", "OK", f"Status: {response.status_code}")
            return True
        else:
            print_status("Backend", "ERROR", f"Status: {response.status_code}")
            return False
    except requests.ConnectionError:
        print_status("Backend", "ERROR", "Connection refused")
        return False
    except requests.Timeout:
        print_status("Backend", "ERROR", "Request timeout")
        return False
    except Exception as e:
        print_status("Backend", "ERROR", str(e))
        return False

def check_nginx_health():
    """Check nginx reverse proxy health"""
    print_header("Nginx Reverse Proxy Health")
    
    try:
        response = requests.get(SERVICES["nginx"], timeout=5)
        if response.status_code == 200:
            print_status("Nginx", "OK", f"Status: {response.status_code}")
            return True
        else:
            print_status("Nginx", "ERROR", f"Status: {response.status_code}")
            return False
    except requests.ConnectionError:
        print_status("Nginx", "ERROR", "Connection refused")
        return False
    except requests.Timeout:
        print_status("Nginx", "ERROR", "Request timeout")
        return False
    except Exception as e:
        print_status("Nginx", "ERROR", str(e))
        return False

def check_mongodb_connection():
    """Check MongoDB connection"""
    print_header("MongoDB Connection")
    
    try:
        # Try to connect to MongoDB from backend
        cmd = """
import asyncio
from motor.motor_asyncio import AsyncClient
from motor.motor_asyncio import AsyncClient

async def test_mongodb():
    uri = "mongodb://hypersend:Mayank%40%2303@mongodb:27017/hypersend?authSource=admin&retryWrites=true"
    try:
        client = AsyncClient(uri, serverSelectionTimeoutMS=5000)
        await client.admin.command('ping')
        await client.close()
        return True
    except Exception as e:
        print(f"MongoDB Error: {e}")
        return False

result = asyncio.run(test_mongodb())
exit(0 if result else 1)
"""
        result = subprocess.run(
            ["python", "-c", cmd],
            capture_output=True,
            timeout=10,
            text=True
        )
        
        if result.returncode == 0:
            print_status("MongoDB", "OK", "Connection successful")
            return True
        else:
            print_status("MongoDB", "ERROR", result.stderr)
            return False
    except subprocess.TimeoutExpired:
        print_status("MongoDB", "ERROR", "Connection timeout")
        return False
    except Exception as e:
        print_status("MongoDB", "ERROR", str(e))
        return False

def check_disk_space():
    """Check disk space"""
    print_header("Disk Space")
    
    try:
        output = subprocess.check_output(
            ["df", "-h", "/root/Hypersend"],
            text=True
        )
        
        lines = output.strip().split('\n')
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 5:
                filesystem = parts[0]
                size = parts[1]
                used = parts[2]
                available = parts[3]
                percent = parts[4]
                
                usage_percent = int(percent.rstrip('%'))
                if usage_percent > 90:
                    status = "WARNING"
                elif usage_percent > 80:
                    status = "WARNING"
                else:
                    status = "OK"
                
                message = f"Used: {used}/{size} ({percent}), Available: {available}"
                print_status("Disk", status, message)
        
        return True
    except Exception as e:
        print_status("Disk", "ERROR", str(e))
        return False

def view_logs(service, lines=20):
    """View recent logs"""
    print_header(f"{service.upper()} Logs (Last {lines} lines)")
    
    try:
        output = subprocess.check_output(
            ["docker-compose", "logs", "--tail", str(lines), service],
            stderr=subprocess.DEVNULL,
            text=True
        )
        print(output)
    except Exception as e:
        print(f"Error viewing logs: {e}")

def main():
    """Main function"""
    print(f"{Colors.BOLD}{Colors.BLUE}")
    print("╔═══════════════════════════════════════════════════╗")
    print(f"║  Hypersend Health Check Monitor                  ║")
    print(f"║  VPS: {VPS_IP:<35}║")
    print(f"║  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<35}║")
    print("╚═══════════════════════════════════════════════════╝")
    print(Colors.RESET)
    
    # Run checks
    services = check_docker_services()
    backend_ok = check_backend_health()
    nginx_ok = check_nginx_health()
    mongodb_ok = check_mongodb_connection()
    check_disk_space()
    
    # Summary
    print_header("Summary")
    all_ok = backend_ok and nginx_ok and mongodb_ok
    
    if all_ok:
        print(f"{Colors.GREEN}{Colors.BOLD}✅ All services operational!{Colors.RESET}")
    else:
        print(f"{Colors.RED}{Colors.BOLD}❌ Some services have issues. Check logs above.{Colors.RESET}")
    
    # Recommendations
    print_header("Recommendations")
    if not backend_ok:
        print("1. Backend is not responding:")
        print("   - Check logs: docker-compose logs backend")
        print("   - Restart: docker-compose restart backend")
        print("   - Rebuild: docker-compose up --build backend -d")
    
    if not nginx_ok:
        print("2. Nginx is not responding:")
        print("   - Check logs: docker-compose logs nginx")
        print("   - Restart: docker-compose restart nginx")
    
    if not mongodb_ok:
        print("3. MongoDB connection failed:")
        print("   - Check MongoDB service: docker-compose ps mongodb")
        print("   - Check logs: docker-compose logs mongodb")
        print("   - Verify credentials in .env.production")
    
    print()
    
    # Exit code
    return 0 if all_ok else 1

if __name__ == "__main__":
    sys.exit(main())
