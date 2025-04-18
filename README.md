# 🔒 4Chat - Secure Communication Redefined

![4Chat Banner](./release-banner.png)

[![Release](https://img.shields.io/github/v/release/4insec/4Chat?include_prereleases)](https://github.com/4insec/4Chat/releases)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

4Chat is a secure, end-to-end encrypted chat application designed for privacy-conscious users. With robust encryption, offline messaging capabilities, and a simple, intuitive interface, 4Chat provides a secure channel for confidential communication.

## ✨ Features

- **🔒 End-to-End Encryption**: All messages are encrypted with strong cryptographic algorithms
- **👥 Contact Management**: Add contacts and communicate only with mutual connections
- **📲 Offline Messaging**: Messages are securely stored and delivered when recipients come online
- **🔔 Desktop Notifications**: Never miss important messages with customizable alerts
- **🔄 Auto Reconnect**: Seamlessly handle connection interruptions
- **🌙 Dark Mode**: Easy on the eyes with a modern interface
- **🔑 Session Management**: Secure authentication with token-based sessions

## 📦 Installation

### Linux Packages

| Platform | Package | Download |
|----------|---------|----------|
| **Debian/Ubuntu** | `.deb` | [blackchat_1.3.0_amd64.deb](https://github.com/4insec/4Chat/releases/latest/download/blackchat_1.3.0_amd64.deb) |

### Manual Installation

#### Prerequisites
- Python 3.8+
- pip
- libssl-dev

```bash
# Clone the repository
git clone https://github.com/4insec/4Chat.git
cd 4Chat

# Install dependencies
pip install -r requirements.txt

# Run the client
python 4chat/client/client.py
```

## 🚀 Usage

After installation, launch 4Chat from your application menu or by running `4Chat` in your terminal.

### Client Commands

| Command | Description |
|---------|-------------|
| `/register` | Create a new account |
| `/login` | Sign in to an existing account |
| `/add <username>` | Add a new contact |
| `/chat <username>` | Start chatting with a contact |
| `/exit` | Exit the current chat |
| `/msg <user> <message>` | Send a one-off message |
| `/contacts` | View your contact list |
| `/clear` | Clear the screen |
| `/quit` | Exit 4Chat |

## 🔧 Server Deployment

4Chat includes a robust server component that can be easily deployed using Docker.

### Using Docker Compose

```bash
# Build and start the server
docker-compose up -d

# View logs
docker-compose logs -f
```

### Manual Server Setup

#### Prerequisites
- Python 3.8+
- Redis server

```bash
# Install server dependencies
pip install -r requirements-server.txt

# Configure Redis
sudo apt install redis-server
sudo systemctl enable redis-server

# Run the server
python 4chat/server/main.py
```

## 🔐 Security

4Chat implements several security features:

- **Public Key Infrastructure**: RSA key pairs for secure key exchange
- **Symmetric Encryption**: AES-256 for message payload encryption
- **Message Authentication**: Prevents tampering with messages
- **Forward Secrecy**: Session keys are regularly rotated
- **Secure Authentication**: Passwords are securely hashed with bcrypt
- **Rate Limiting**: Prevents brute force attacks

## 🛠️ Development

### Building from Source

```bash
# Build the Debian package
./build.sh

# Build with server Docker setup
./build.sh --with-server
```

### Project Structure

```
4Chat/
├── 4chat/
│   ├── client/       # Client application code
│   ├── server/       # Server application code
│   └── assets/       # Icons, sounds and resources
├── docs/             # Documentation
└── scripts/          # Build and utility scripts
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Contact

4INSEC - [info@4insec.com](mailto:info@4insec.com)

Project Link: [https://github.com/4insec/4Chat](https://github.com/4insec/4Chat)