#!/bin/bash
set -e  # Exit on error

# Version and build info
VERSION="1.3.0"
BUILD_DATE=$(date +"%Y-%m-%d")
PACKAGE_NAME="4Chat"
ARCHITECTURE="amd64"

echo "===== Building 4Chat v$VERSION ====="
echo "Build Date: $BUILD_DATE"

# Clean previous builds
echo "Cleaning previous builds..."
rm -rf build dist package

# Create virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi

# Activate virtual environment and install dependencies
echo "Installing dependencies..."
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install pyinstaller

# Create necessary directories
echo "Creating package structure..."
mkdir -p package/usr/{bin,share/$PACKAGE_NAME/{assets,sounds}}
mkdir -p package/DEBIAN
mkdir -p package/etc/$PACKAGE_NAME
mkdir -p package/usr/share/applications
mkdir -p package/usr/share/icons/hicolor/{16x16,32x32,48x48,64x64,128x128}/apps

# Build client using venv's pyinstaller
echo "Building client binary..."
.venv/bin/pyinstaller --clean --onefile --name $PACKAGE_NAME \
--add-data "4chat/assets/notification.png:assets" \
--add-data "4chat/assets/sounds/message.oga:assets/sounds" \
--add-data "4chat/assets/icon.png:assets" \
--hidden-import=websockets \
--hidden-import=plyer.platforms.linux.notification \
--hidden-import=cryptography \
4chat/client/client.py

# Copy files to package
echo "Copying files to package..."
cp dist/$PACKAGE_NAME package/usr/bin/
cp 4chat/assets/notification.png package/usr/share/$PACKAGE_NAME/assets/
cp 4chat/assets/sounds/message.oga package/usr/share/$PACKAGE_NAME/sounds/
cp 4chat/assets/icon.png package/usr/share/$PACKAGE_NAME/assets/

# Copy icons for different resolutions
for size in 16 32 48 64 128; do
    if [ -f "4chat/assets/icons/icon-${size}x${size}.png" ]; then
        cp "4chat/assets/icons/icon-${size}x${size}.png" "package/usr/share/icons/hicolor/${size}x${size}/apps/$PACKAGE_NAME.png"
    else
        # If specific size doesn't exist, use the main icon
        cp "4chat/assets/icon.png" "package/usr/share/icons/hicolor/${size}x${size}/apps/$PACKAGE_NAME.png"
    fi
done

# Create desktop entry
cat > package/usr/share/applications/$PACKAGE_NAME.desktop << EOL
[Desktop Entry]
Version=1.0
Type=Application
Name=4Chat
Comment=Secure Chat Client
Exec=$PACKAGE_NAME
Icon=$PACKAGE_NAME
Terminal=true
Categories=Network;Chat;
Keywords=chat;secure;encryption;
EOL

# Create default config
cat > package/etc/$PACKAGE_NAME/config.json << EOL
{
    "server_url": "wss://chat.giwatech.site",
    "notification_sound": true,
    "notification_display": true,
    "auto_reconnect": true,
    "theme": "dark"
}
EOL

# Create control file
cat > package/DEBIAN/control << EOL
Package: $PACKAGE_NAME
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCHITECTURE
Maintainer: 4INSEC <mwaijegakelvin@gmail.com>
Description: Secure End-to-End Encrypted Chat Client
 4Chat is a secure messaging application that provides
 end-to-end encryption, offline messaging, and secure 
 authentication. It's designed for privacy-conscious users
 who need reliable and secure communication.
Homepage: https://4insec.com
Depends: python3 (>= 3.8), libssl-dev, python3-cryptography, python3-websockets, python3-plyer
EOL

# Create postinst script to set permissions
cat > package/DEBIAN/postinst << EOL
#!/bin/bash
# Create necessary directories in user's home directory
mkdir -p ~/.4Chat/{logs,history}
chmod 700 ~/.4Chat
chmod 700 ~/.4Chat/logs
chmod 700 ~/.4Chat/history
exit 0
EOL
chmod 755 package/DEBIAN/postinst

# Create prerm script to clean up
cat > package/DEBIAN/prerm << EOL
#!/bin/bash
# No need to remove user data
exit 0
EOL
chmod 755 package/DEBIAN/prerm

# Build Debian package
echo "Building Debian package..."
dpkg-deb --build package ${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE}.deb

# Build server docker image if requested
if [ "$1" == "--with-server" ]; then
    echo "Building server Docker image..."
    
    # Create Dockerfile
    cat > Dockerfile << EOL
FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \\
    build-essential \\
    libssl-dev \\
    && rm -rf /var/lib/apt/lists/*

# Copy application code
COPY 4chat/server /app/server
COPY requirements-server.txt /app/

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements-server.txt

# Set environment variables
ENV PYTHONUNBUFFERED=1 \\
    REDIS_HOST=redis \\
    HOST=0.0.0.0

# Expose port
EXPOSE 8765

# Run the server
CMD ["python", "server/main.py"]
EOL

    # Create docker-compose.yml
    cat > docker-compose.yml << EOL
version: '3'

services:
  redis:
    image: redis:alpine
    volumes:
      - redis_data:/data
    restart: unless-stopped
    command: redis-server --appendonly yes
    
  4Chat-server:
    build: .
    depends_on:
      - redis
    ports:
      - "8765:8765"
    volumes:
      - ./ssl:/app/ssl
    environment:
      - REDIS_HOST=redis
      - HOST=0.0.0.0
      - PORT=8765
      - SSL_CERT=/app/ssl/cert.pem
      - SSL_KEY=/app/ssl/key.pem
    restart: unless-stopped

volumes:
  redis_data:
EOL

    # Create requirements-server.txt
    cat > requirements-server.txt << EOL
websockets>=10.4
redis>=4.3.4
bcrypt>=4.0.1
cryptography>=37.0.4
EOL

    echo "Docker setup completed. Use 'docker-compose up -d' to start the server."
fi

echo "Package built: ${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE}.deb"

# Deactivate virtual environment
deactivate

echo "Build completed successfully!"