import asyncio
import websockets
import json
import redis
import bcrypt
import secrets
import uuid
import ssl
import time
import os
import logging
import signal
from datetime import datetime, timedelta
from typing import Dict, Set, Optional, List, Any
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dataclasses import dataclass, asdict
from websockets.exceptions import ConnectionClosed
from redis.exceptions import ConnectionError as RedisConnectionError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("server.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("BlackChatServer")

# Generate a random encryption key or load from environment
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', Fernet.generate_key())
cipher_suite = Fernet(ENCRYPTION_KEY)

# Redis connection with connection pooling and retry mechanism
REDIS_HOST = os.environ.get('REDIS_HOST', '127.0.0.1')
REDIS_PORT = int(os.environ.get('REDIS_PORT', 6379))
REDIS_DB = int(os.environ.get('REDIS_DB', 0))
REDIS_PASSWORD = os.environ.get('REDIS_PASSWORD', None)

redis_pool = redis.ConnectionPool(
    host=REDIS_HOST,
    port=REDIS_PORT,
    db=REDIS_DB,
    password=REDIS_PASSWORD,
    decode_responses=True,
    max_connections=100
)

def get_redis_connection():
    """Get a Redis connection from the pool with retry mechanism."""
    for attempt in range(3):
        try:
            return redis.Redis(connection_pool=redis_pool)
        except RedisConnectionError:
            if attempt < 2:  # Don't sleep on the last attempt
                time.sleep(1 * (2 ** attempt))  # Exponential backoff
            else:
                raise
    raise RuntimeError("Failed to connect to Redis after multiple attempts")

# Initialize Redis connection
r = get_redis_connection()
pubsub = r.pubsub(ignore_subscribe_messages=True)

# Session management
@dataclass
class Session:
    """User session data."""
    username: str
    token: str
    created_at: float
    expires_at: float
    public_key: Optional[str] = None
    session_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary."""
        return asdict(self)

class SessionManager:
    """Manage user sessions with Redis."""
    
    def __init__(self, redis_client):
        self.redis = redis_client
        self.expiry_time = 30 * 24 * 60 * 60  # 30 days in seconds
    
    def create_session(self, username: str, public_key: Optional[str] = None, session_id: Optional[str] = None) -> Session:
        """Create a new session for a user."""
        token = secrets.token_hex(32)
        now = time.time()
        expires_at = now + self.expiry_time
        
        session = Session(
            username=username,
            token=token,
            created_at=now,
            expires_at=expires_at,
            public_key=public_key,
            session_id=session_id or str(uuid.uuid4())
        )
        
        # Store session in Redis
        self.redis.hset(f"session:{token}", mapping=session.to_dict())
        self.redis.expire(f"session:{token}", self.expiry_time)
        
        # Store token by username for lookup
        self.redis.hset("user_sessions", username, token)
        
        return session
    
    def get_session(self, token: str) -> Optional[Session]:
        """Get session by token."""
        session_data = self.redis.hgetall(f"session:{token}")
        if not session_data:
            return None
            
        # Convert types
        session_data['created_at'] = float(session_data['created_at'])
        session_data['expires_at'] = float(session_data['expires_at'])
        
        # Check expiry
        if session_data['expires_at'] < time.time():
            self.invalidate_session(token)
            return None
            
        return Session(**session_data)
    
    def get_user_session(self, username: str) -> Optional[Session]:
        """Get session by username."""
        token = self.redis.hget("user_sessions", username)
        if not token:
            return None
            
        return self.get_session(token)
    
    def update_session(self, token: str, public_key: Optional[str] = None) -> Optional[Session]:
        """Update a session with new information."""
        session = self.get_session(token)
        if not session:
            return None
            
        if public_key:
            session.public_key = public_key
            
        # Update expiry
        now = time.time()
        session.expires_at = now + self.expiry_time
        
        # Update in Redis
        self.redis.hset(f"session:{token}", mapping=session.to_dict())
        self.redis.expire(f"session:{token}", self.expiry_time)
        
        return session
    
    def invalidate_session(self, token: str) -> bool:
        """Invalidate a session."""
        session = self.get_session(token)
        if not session:
            return False
            
        # Remove from Redis
        self.redis.delete(f"session:{token}")
        self.redis.hdel("user_sessions", session.username)
        
        return True
    
    def invalidate_user_sessions(self, username: str) -> bool:
        """Invalidate all sessions for a user."""
        token = self.redis.hget("user_sessions", username)
        if not token:
            return False
            
        # Remove from Redis
        self.redis.delete(f"session:{token}")
        self.redis.hdel("user_sessions", username)
        
        return True

# Message encryption functions
def encrypt_message(message: str) -> str:
    """Encrypt a message using Fernet."""
    return cipher_suite.encrypt(message.encode('utf-8')).decode('utf-8')

def decrypt_message(encrypted_message: str) -> str:
    """Decrypt a message using Fernet."""
    return cipher_suite.decrypt(encrypted_message.encode('utf-8')).decode('utf-8')

# Rate limiting
class RateLimiter:
    """Implement rate limiting for API calls."""
    
    def __init__(self, redis_client, limit: int = 100, window: int = 60):
        self.redis = redis_client
        self.limit = limit  # Max requests per window
        self.window = window  # Time window in seconds
    
    async def check_rate_limit(self, key: str) -> bool:
        """Check if a key has exceeded rate limit."""
        current = int(time.time())
        window_key = f"rate:{key}:{current // self.window}"
        
        # Use pipeline for atomic operations
        pipe = self.redis.pipeline()
        pipe.incr(window_key)
        pipe.expire(window_key, self.window)
        result = pipe.execute()
        
        count = result[0]
        return count <= self.limit

class ChatServer:
    def __init__(self):
        self.connections: Dict[str, websockets.WebSocketServerProtocol] = {}  # Active WebSocket connections
        self.online_users: Set[str] = set()  # Track online users
        self.session_manager = SessionManager(r)
        self.rate_limiter = RateLimiter(r)
        
        # Keep track of session ID to username mapping
        self.session_to_user: Dict[str, str] = {}
        
        # Public key storage
        self.public_keys: Dict[str, str] = {}
    
    async def handle_auth(self, websocket, data) -> Dict[str, Any]:
        """Handle authentication logic."""
        try:
            username = data.get('username', '').strip()
            password = data.get('password', '')
            public_key = data.get('public_key')
            session_id = data.get('session_id')
            
            # Rate limiting for auth attempts
            client_ip = websocket.remote_address[0]
            if not await self.rate_limiter.check_rate_limit(f"auth:{client_ip}"):
                logger.warning(f"Rate limit exceeded for auth from {client_ip}")
                return {'success': False, 'message': 'Too many authentication attempts. Please try again later.'}
            
            if data['type'] == 'register':
                # Validate username
                if not username or len(username) < 3 or len(username) > 20:
                    return {'success': False, 'message': 'Username must be between 3 and 20 characters'}
                
                # Check for existing user
                if r.hexists("users", username):
                    return {'success': False, 'message': 'Username already taken'}
                
                # Validate password strength
                if len(password) < 8:
                    return {'success': False, 'message': 'Password must be at least 8 characters'}
                
                # Hash and store password
                hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
                r.hset("users", username, hashed.decode('utf-8'))
                
                # Create session
                session = self.session_manager.create_session(username, public_key, session_id)
                
                # Store public key if provided
                if public_key:
                    self.public_keys[username] = public_key
                
                logger.info(f"User registered: {username}")
                return {
                    'success': True, 
                    'message': 'Registration successful',
                    'token': session.token
                }
                
            elif data['type'] == 'login':
                # Get stored password hash
                hashed_password = r.hget("users", username)
                if not hashed_password:
                    logger.warning(f"Login attempt for non-existent user: {username}")
                    # Use same message to prevent username enumeration
                    return {'success': False, 'message': 'Invalid credentials'}
                
                # Verify password
                if not bcrypt.checkpw(password.encode(), hashed_password.encode()):
                    logger.warning(f"Failed login attempt for user: {username}")
                    return {'success': False, 'message': 'Invalid credentials'}
                
                # Invalidate previous sessions
                self.session_manager.invalidate_user_sessions(username)
                
                # Create new session
                session = self.session_manager.create_session(username, public_key, session_id)
                
                # Store public key if provided
                if public_key:
                    self.public_keys[username] = public_key
                
                logger.info(f"User logged in: {username}")
                return {
                    'success': True, 
                    'message': 'Login successful',
                    'token': session.token
                }
                
            elif data['type'] == 'token_auth':
                token = data.get('token')
                if not token:
                    return {'success': False, 'message': 'Invalid token'}
                
                # Verify token
                session = self.session_manager.get_session(token)
                if not session or session.username != username:
                    logger.warning(f"Invalid token auth attempt for user: {username}")
                    return {'success': False, 'message': 'Session expired or invalid'}
                
                # Update session with new public key if provided
                if public_key:
                    self.session_manager.update_session(token, public_key)
                    self.public_keys[username] = public_key
                
                logger.info(f"User authenticated with token: {username}")
                return {
                    'success': True, 
                    'message': 'Authentication successful'
                }
            
            return {'success': False, 'message': 'Invalid authentication type'}

        except Exception as e:
            logger.error(f"Auth error: {str(e)}", exc_info=True)
            return {'success': False, 'message': 'Authentication error. Please try again.'}
    
    async def handle_connection(self, websocket, path):
        """Handle a WebSocket connection."""
        username = None
        client_ip = websocket.remote_address[0]
        session_id = None
        
        try:
            # Implement connection rate limiting
            if not await self.rate_limiter.check_rate_limit(f"conn:{client_ip}"):
                logger.warning(f"Connection rate limit exceeded from {client_ip}")
                await websocket.send(json.dumps({
                    'type': 'error',
                    'message': 'Too many connection attempts. Please try again later.'
                }))
                return
            
            # Allow multiple auth attempts
            while True:
                try:
                    # Set a timeout for receiving the auth message
                    auth_message = await asyncio.wait_for(websocket.recv(), timeout=30.0)
                    auth_data = json.loads(auth_message)
                    
                    # Extract session ID if provided
                    session_id = auth_data.get('session_id')
                    
                    auth_result = await self.handle_auth(websocket, auth_data)
                    
                    # Send ONLY the auth result first
                    await websocket.send(json.dumps(auth_result))
            
                    if auth_result.get('success'):
                        username = auth_data['username']
                        self.connections[username] = websocket
                        self.online_users.add(username)
                        
                        # Store session mapping
                        if session_id:
                            self.session_to_user[session_id] = username
                        
                        # Send contacts and online status AFTER auth confirmation
                        await self.send_contact_list(username)
                        await self.send_online_status(username)
                        
                        # Decrypt and send pending messages
                        await self.send_pending_messages(username)
                        
                        # Notify contacts about online status
                        await self.notify_contacts(username, True)
                        break  # Exit auth loop
                    
                except asyncio.TimeoutError:
                    logger.warning(f"Auth timeout for connection from {client_ip}")
                    await websocket.send(json.dumps({
                        'type': 'error',
                        'message': 'Authentication timeout. Please try again.'
                    }))
                    return
                
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON received from {client_ip}")
                    await websocket.send(json.dumps({
                        'type': 'error',
                        'message': 'Invalid message format. Please try again.'
                    }))
            
            # Handle messages after successful auth
            async for message in websocket:
                # Implement message rate limiting
                if not await self.rate_limiter.check_rate_limit(f"msg:{username}"):
                    logger.warning(f"Message rate limit exceeded for {username}")
                    await websocket.send(json.dumps({
                        'type': 'error',
                        'message': 'Sending too many messages. Please slow down.'
                    }))
                    continue
                
                try:
                    data = json.loads(message)
                    
                    # Route message based on type
                    if data['type'] == 'add_contact':
                        await self.add_contact(username, data['contact'])
                    elif data['type'] == 'message':
                        await self.route_message(username, data)
                    elif data['type'] == 'key_exchange' or data['type'] == 'key_exchange_response':
                        await self.handle_key_exchange(username, data)
                    else:
                        logger.warning(f"Unknown message type from {username}: {data['type']}")
                
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON in message from {username}")
                    await websocket.send(json.dumps({
                        'type': 'error',
                        'message': 'Invalid message format'
                    }))
    
        except websockets.ConnectionClosed as e:
            logger.info(f"Connection closed: {e.code} {e.reason}")
        except Exception as e:
            logger.error(f"Connection error: {str(e)}", exc_info=True)
        finally:
            if username:
                if username in self.connections:
                    del self.connections[username]
                if username in self.online_users:
                    self.online_users.remove(username)
                    await self.notify_contacts(username, False)
                
                # Remove session mapping
                if session_id and session_id in self.session_to_user:
                    del self.session_to_user[session_id]
                
                logger.info(f"User disconnected: {username}")
    
    async def send_contact_list(self, username):
        """Send contact list to user."""
        try:
            contacts = r.smembers(f"contacts:{username}")
            await self.connections[username].send(json.dumps({
                'type': 'contact_list',
                'contacts': list(contacts)
            }))
        except Exception as e:
            logger.error(f"Error sending contact list to {username}: {str(e)}")
    
    async def send_online_status(self, username):
        """Send online status of contacts to user."""
        try:
            contacts = r.smembers(f"contacts:{username}")
            for contact in contacts:
                if contact in self.online_users:
                    await self.connections[username].send(json.dumps({
                        'type': 'status',
                        'user': contact,
                        'status': 'online'
                    }))
        except Exception as e:
            logger.error(f"Error sending online status to {username}: {str(e)}")
    
    async def send_pending_messages(self, username):
        """Decrypt and send pending messages to user."""
        try:
            pending_messages = r.lrange(f"messages:{username}", 0, -1)
            for msg in pending_messages:
                msg_data = json.loads(msg)
                
                # Check if message is encrypted with server encryption
                if not msg_data.get('client_encrypted', False):
                    # Decrypt server-side encryption
                    msg_data['message'] = decrypt_message(msg_data['message'])
                
                await self.connections[username].send(json.dumps(msg_data))
            
            # Clear pending messages
            r.delete(f"messages:{username}")
        except Exception as e:
            logger.error(f"Error sending pending messages to {username}: {str(e)}")
    
    async def add_contact(self, username, contact):
        """Add a contact with mutual check and validation."""
        try:
            # Validate contact username
            if not contact or len(contact) < 3:
                await self.connections[username].send(json.dumps({
                    'type': 'error',
                    'message': 'Invalid contact username'
                }))
                return
                
            # Prevent adding self
            if username == contact:
                await self.connections[username].send(json.dumps({
                    'type': 'error',
                    'message': 'You cannot add yourself as a contact'
                }))
                return

            # Check if contact exists
            if not r.hexists("users", contact):
                await self.connections[username].send(json.dumps({
                    'type': 'error',
                    'message': f'User {contact} does not exist'
                }))
                return

            # Check if already in contacts
            if r.sismember(f"contacts:{username}", contact):
                await self.connections[username].send(json.dumps({
                    'type': 'error',
                    'message': f'{contact} is already in your contacts'
                }))
                return

            # Add contact
            r.sadd(f"contacts:{username}", contact)
            await self.connections[username].send(json.dumps({
                'type': 'system',
                'message': f'{contact} added to your contacts'
            }))

            # Update contact list for user
            await self.send_contact_list(username)

            # Notify both users if mutual contact
            if r.sismember(f"contacts:{contact}", username):
                await self.connections[username].send(json.dumps({
                    'type': 'system',
                    'message': f'You are now mutual contacts with {contact}'
                }))
                
                if contact in self.connections:
                    await self.connections[contact].send(json.dumps({
                        'type': 'system',
                        'message': f'You are now mutual contacts with {username}'
                    }))
                    
                    # Send online status to both
                    await self.connections[username].send(json.dumps({
                        'type': 'status',
                        'user': contact,
                        'status': 'online' if contact in self.online_users else 'offline'
                    }))
                    
                    await self.connections[contact].send(json.dumps({
                        'type': 'status',
                        'user': username,
                        'status': 'online'
                    }))

        except Exception as e:
            logger.error(f"Error adding contact for {username}: {str(e)}")
            await self.connections[username].send(json.dumps({
                'type': 'error',
                'message': 'Failed to add contact. Please try again.'
            }))

    async def handle_key_exchange(self, sender, data):
        """Handle key exchange for E2E encryption."""
        try:
            message_type = data['type']
            receiver = data['to']
            public_key = data['public_key']
            
            # Store public key
            self.public_keys[sender] = public_key
            
            # Prepare message
            message_data = {
                'type': message_type,
                'from': sender,
                'public_key': public_key,
                'timestamp': datetime.now().isoformat()
            }
            
            # Send key to receiver if online
            if receiver in self.connections:
                await self.connections[receiver].send(json.dumps(message_data))
            else:
                # Store for later delivery
                r.rpush(f"messages:{receiver}", json.dumps(message_data))
                
                await self.connections[sender].send(json.dumps({
                    'type': 'system',
                    'message': f"{receiver} is offline. Key exchange will complete when they're back."
                }))
                
        except Exception as e:
            logger.error(f"Key exchange error: {str(e)}")
            await self.connections[sender].send(json.dumps({
                'type': 'error',
                'message': 'Failed to exchange keys'
            }))

    async def route_message(self, sender, data):
        """Route messages with mutual contact verification and encryption."""
        try:
            receiver = data['to']
            
            # Check receiver existence
            if not r.hexists("users", receiver):
                await self.connections[sender].send(json.dumps({
                    'type': 'error',
                    'message': f"User {receiver} does not exist"
                }))
                return
        
            # Check mutual contacts
            if not (r.sismember(f"contacts:{sender}", receiver) and r.sismember(f"contacts:{receiver}", sender)):
                await self.connections[sender].send(json.dumps({
                    'type': 'error',
                    'message': f"You can only message mutual contacts. {receiver} needs to add you back."
                }))
                return
        
            # Check message size
            message = data['message']
            if len(message) > 16384:  # 16KB limit
                await self.connections[sender].send(json.dumps({
                    'type': 'error',
                    'message': f"Message too large. Maximum size is 16KB."
                }))
                return
        
            # Generate timestamp
            timestamp = datetime.now().isoformat()
            
            # Check if message is already client-encrypted
            is_encrypted = data.get('encrypted', False)
            
            # Construct message data
            message_data = {
                'type': 'message',
                'from': sender,
                'message': message,
                'timestamp': timestamp,
                'encrypted': is_encrypted,
                'client_encrypted': is_encrypted
            }
            
            # If not client-encrypted, encrypt with server encryption
            if not is_encrypted:
                message_data['message'] = encrypt_message(message)
        
            if receiver in self.connections:
                # If receiver is online, send message directly
                await self.connections[receiver].send(json.dumps(message_data))
                
                # Record message in history
                r.lpush(f"history:{sender}:{receiver}", json.dumps(message_data))
                r.lpush(f"history:{receiver}:{sender}", json.dumps(message_data))
                r.ltrim(f"history:{sender}:{receiver}", 0, 99)  # Keep last 100 messages
                r.ltrim(f"history:{receiver}:{sender}", 0, 99)
            else:
                # Store message for offline user
                r.rpush(f"messages:{receiver}", json.dumps(message_data))
                await self.connections[sender].send(json.dumps({
                    'type': 'system',
                    'message': f"{receiver} is offline. Message will be delivered when they're back."
                }))
        
        except Exception as e:
            logger.error(f"Message routing error: {str(e)}")
            await self.connections[sender].send(json.dumps({
                'type': 'error',
                'message': 'Failed to send message'
            }))
    
    async def notify_contacts(self, username, is_online):
        """Notify contacts about a user's status change."""
        try:
            contacts = r.smembers(f"contacts:{username}")
            for contact in contacts:
                if contact in self.connections:
                    await self.connections[contact].send(json.dumps({
                        'type': 'status',
                        'user': username,
                        'status': 'online' if is_online else 'offline'
                    }))
        except Exception as e:
            logger.error(f"Error notifying contacts of {username}: {str(e)}")

async def cleanup(server):
    """Cleanup resources when shutting down."""
    logger.info("Shutting down server...")
    
    # Close all WebSocket connections
    close_tasks = []
    for username, websocket in server.connections.items():
        close_tasks.append(asyncio.create_task(websocket.close(1001, "Server shutting down")))
    
    if close_tasks:
        await asyncio.wait(close_tasks)
    
    # Close Redis pool
    redis_pool.disconnect()
    logger.info("Server shutdown complete")

async def main():
    server = ChatServer()
    
    # Setup SSL context for secure WebSockets
    ssl_context = None
    cert_file = os.environ.get('SSL_CERT', '')
    key_file = os.environ.get('SSL_KEY', '')
    
    if cert_file and key_file and os.path.exists(cert_file) and os.path.exists(key_file):
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(cert_file, key_file)
        logger.info("SSL enabled with provided certificate")
    
    # Get host and port from environment or use defaults
    host = os.environ.get('HOST', 'localhost')
    port = int(os.environ.get('PORT', 8765))
    
    # Register signal handlers for graceful shutdown
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(cleanup(server)))
    
    # Start server
    logger.info(f"Starting server on {'wss' if ssl_context else 'ws'}://{host}:{port}")
    async with websockets.serve(
        server.handle_connection, 
        host, 
        port, 
        ssl=ssl_context,
        ping_interval=30,
        ping_timeout=60,
        max_size=2**20,  # 1MB message size limit
        max_queue=64     # Connection queue size
    ) as ws_server:
        logger.info(f"Server successfully started! Listening on {ws_server.sockets[0].getsockname()}")
        
        # Keep server running until shutdown
        await asyncio.Future()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Server stopped by keyboard interrupt")
    except Exception as e:
        logger.error(f"Server error: {str(e)}", exc_info=True)