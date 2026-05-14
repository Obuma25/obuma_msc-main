#!/bin/bash
# EC2 User Data Script
# Installs Docker and deploys OWASP Juice Shop

set -e  # Exit on error

# Log output to file
exec > >(tee -a /var/log/user-data.log)
exec 2>&1

echo "========================================="
echo "Starting EC2 initialization"
echo "Time: $(date)"
echo "========================================="

# Update package repositories
echo "Updating package repositories..."
apt-get update -y

# Install Docker
echo "Installing Docker..."
apt-get install -y docker.io

# Start and enable Docker service
echo "Starting Docker service..."
systemctl start docker
systemctl enable docker

# Add ubuntu user to docker group
echo "Adding ubuntu user to docker group..."
usermod -aG docker ubuntu

# Wait for Docker to be fully ready
sleep 10

# Pull OWASP Juice Shop image
echo "Pulling OWASP Juice Shop image..."
docker pull bkimminich/juice-shop:v16.0.1

# Create CloudWatch Logs configuration (if not exists)
mkdir -p /etc/docker
cat > /etc/docker/daemon.json <<EOF
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
EOF

# Restart Docker to apply log configuration
systemctl restart docker
sleep 5

# Deploy Juice Shop container
echo "Deploying OWASP Juice Shop..."
docker run -d \
  --name juice-shop \
  --restart unless-stopped \
  -p 80:3000 \
  --memory="768m" \
  --cpus="0.5" \
  bkimminich/juice-shop:v16.0.1

# Wait for container to start
sleep 15

# Check if container is running
if docker ps | grep -q juice-shop; then
    echo "========================================="
    echo "SUCCESS: Juice Shop is running!"
    echo "Container ID: $(docker ps --filter name=juice-shop --format '{{.ID}}')"
    echo "Status: $(docker ps --filter name=juice-shop --format '{{.Status}}')"
    echo "========================================="
else
    echo "ERROR: Juice Shop failed to start"
    docker logs juice-shop
    exit 1
fi

# Install useful tools
echo "Installing diagnostic tools..."
apt-get install -y curl wget net-tools dnsutils

echo "========================================="
echo "EC2 initialization complete"
echo "Time: $(date)"
echo "Access Juice Shop at: http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)"
echo "========================================="
