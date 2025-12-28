#!/bin/bash
# Zero Trust NMS - Quick Start Script

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║          Zero Trust Network Management System                ║"
echo "║                    Quick Start Script                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check prerequisites
echo -e "${YELLOW}Checking prerequisites...${NC}"

check_command() {
    if ! command -v $1 &> /dev/null; then
        echo -e "${RED}Error: $1 is not installed${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓${NC} $1 found"
}

check_command docker
check_command docker-compose

# Check Docker daemon
if ! docker info &> /dev/null; then
    echo -e "${RED}Error: Docker daemon is not running${NC}"
    exit 1
fi
echo -e "${GREEN}✓${NC} Docker daemon is running"

# Setup environment
echo ""
echo -e "${YELLOW}Setting up environment...${NC}"

cd deployments/docker

if [ ! -f .env ]; then
    echo "Creating .env file from template..."
    cp .env.example .env
    
    # Generate random passwords
    POSTGRES_PASS=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 24)
    REDIS_PASS=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 24)
    GRAFANA_PASS=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 16)
    
    # Update passwords in .env (compatible with both Linux and macOS)
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s/POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=${POSTGRES_PASS}/" .env
        sed -i '' "s/REDIS_PASSWORD=.*/REDIS_PASSWORD=${REDIS_PASS}/" .env
        sed -i '' "s/GRAFANA_PASSWORD=.*/GRAFANA_PASSWORD=${GRAFANA_PASS}/" .env
    else
        sed -i "s/POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=${POSTGRES_PASS}/" .env
        sed -i "s/REDIS_PASSWORD=.*/REDIS_PASSWORD=${REDIS_PASS}/" .env
        sed -i "s/GRAFANA_PASSWORD=.*/GRAFANA_PASSWORD=${GRAFANA_PASS}/" .env
    fi
    
    echo -e "${GREEN}✓${NC} Environment configured with random passwords"
else
    echo -e "${GREEN}✓${NC} .env file already exists"
fi

# Start services
echo ""
echo -e "${YELLOW}Starting services...${NC}"

docker-compose pull 2>/dev/null || true
docker-compose up -d postgres redis nats etcd

echo "Waiting for database to be ready..."
sleep 10

# Check if postgres is ready
for i in {1..30}; do
    if docker exec zt-nms-postgres pg_isready -U ztnms &> /dev/null; then
        echo -e "${GREEN}✓${NC} PostgreSQL is ready"
        break
    fi
    if [ $i -eq 30 ]; then
        echo -e "${RED}Error: PostgreSQL failed to start${NC}"
        exit 1
    fi
    sleep 1
done

# Initialize database
echo ""
echo -e "${YELLOW}Initializing database...${NC}"

if docker exec zt-nms-postgres psql -U ztnms -d ztnms -c "SELECT 1 FROM identities LIMIT 1" &> /dev/null; then
    echo -e "${GREEN}✓${NC} Database already initialized"
else
    docker exec -i zt-nms-postgres psql -U ztnms -d ztnms < ../database/schema.sql
    echo -e "${GREEN}✓${NC} Database schema applied"
fi

# Start remaining services
echo ""
echo -e "${YELLOW}Starting application services...${NC}"

docker-compose up -d

# Wait for API Gateway
echo "Waiting for API Gateway to be ready..."
for i in {1..60}; do
    if curl -sk https://localhost:8080/health &> /dev/null; then
        echo -e "${GREEN}✓${NC} API Gateway is ready"
        break
    fi
    if [ $i -eq 60 ]; then
        echo -e "${YELLOW}Warning: API Gateway may still be starting${NC}"
    fi
    sleep 2
done

# Summary
echo ""
echo -e "${GREEN}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    Setup Complete!                           ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo "Services are available at:"
echo ""
echo -e "  ${GREEN}API Gateway${NC}:    https://localhost:8080"
echo -e "  ${GREEN}Health Check${NC}:   https://localhost:8080/health"
echo -e "  ${GREEN}Metrics${NC}:        http://localhost:9090/metrics"
echo -e "  ${GREEN}Grafana${NC}:        http://localhost:3000 (admin/${GRAFANA_PASS:-see .env})"
echo -e "  ${GREEN}Jaeger${NC}:         http://localhost:16686"
echo ""
echo "To check status:   docker-compose ps"
echo "To view logs:      docker-compose logs -f api-gateway"
echo "To stop:           docker-compose down"
echo ""
echo -e "${YELLOW}Note: The API uses a self-signed certificate. Use -k with curl.${NC}"
echo ""

# Test API
echo "Testing API..."
HEALTH=$(curl -sk https://localhost:8080/health 2>/dev/null || echo "failed")
if echo "$HEALTH" | grep -q "healthy"; then
    echo -e "${GREEN}✓ API is responding correctly${NC}"
else
    echo -e "${YELLOW}! API may still be starting. Check logs with: docker-compose logs api-gateway${NC}"
fi

cd ../..
