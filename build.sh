#!/bin/bash

# Clean previous builds
rm -rf build dist package

# Create necessary directories
mkdir -p package/usr/{bin,share/4chat-client}
mkdir -p package/DEBIAN

# Build client using venv's pyinstaller
.venv/bin/pyinstaller --onefile --name 4chat-client \
--add-data "4chat/assets/notification.png:assets" \
--hidden-import=websockets \
--hidden-import=plyer.platforms.linux.notification \
4chat/client/client.py

# Copy files to package
cp dist/4chat-client package/usr/bin/
cp 4chat/assets/notification.png package/usr/share/4chat-client/

# Create control file
cat <<EOL > package/DEBIAN/control
Package: 4chat-client
Version: 1.0
Section: net
Priority: optional
Architecture: amd64
Maintainer: 4INSEC <admin@4insec.com>
Description: Secure Chat Client for 4INSEC
Homepage: https://4insec.com
Depends: python3, python3-websockets, python3-plyer
EOL

# Build Debian package
dpkg-deb --build package 4chat-client_1.0_amd64.deb

echo "Package built: 4chat-client_1.0_amd64.deb"