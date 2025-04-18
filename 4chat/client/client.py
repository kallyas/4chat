import asyncio
import websockets
import json
import logging
import ssl
import random
import os
import platform
import warnings
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from websockets.exceptions import ConnectionClosed
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.styles import Style
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.history import FileHistory
from plyer import notification
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

# Initialize rich console with force_terminal=False
console = Console(force_terminal=False)

# Suppress plyer warnings about missing dbus
warnings.filterwarnings("ignore", category=UserWarning, module="plyer")

# Setup logging with rotating file handler
from logging.handlers import RotatingFileHandler
log_dir = os.path.join(os.path.expanduser("~"), ".4Chat", "logs")
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, "4Chat.log")

logger = logging.getLogger("4Chat")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(log_file, maxBytes=1024*1024, backupCount=3)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# Define prompt_toolkit style
prompt_style = Style.from_dict({
    "prompt": "cyan",
    "bottom_toolbar": "green",
    "username": "bold cyan",
    "error": "bold red",
    "system": "yellow",
})

class E2EEncryption:
    """End-to-end encryption handler"""
    
    def __init__(self):
        # Generate RSA key pair for key exchange
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        
        # Dictionary to store Fernet keys for each contact
        self.contact_keys = {}
        
    def get_public_key_pem(self) -> str:
        """Get PEM-encoded public key"""
        from cryptography.hazmat.primitives import serialization
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return b64encode(pem).decode('utf-8')
        
    def set_contact_public_key(self, username: str, public_key_pem: str) -> None:
        """Store public key for a contact and generate shared key"""
        from cryptography.hazmat.primitives import serialization
        
        # Decode and deserialize public key
        public_key_bytes = b64decode(public_key_pem)
        public_key = serialization.load_pem_public_key(public_key_bytes)
        
        # Generate a random Fernet key for this contact
        salt = os.urandom(16)
        key = Fernet.generate_key()
        
        # Store the key
        self.contact_keys[username] = key
        
    def encrypt_message(self, recipient: str, message: str) -> str:
        """Encrypt a message for a specific recipient"""
        if recipient not in self.contact_keys:
            raise ValueError(f"No encryption key for {recipient}")
            
        cipher = Fernet(self.contact_keys[recipient])
        return b64encode(cipher.encrypt(message.encode('utf-8'))).decode('utf-8')
        
    def decrypt_message(self, sender: str, encrypted_message: str) -> str:
        """Decrypt a message from a specific sender"""
        if sender not in self.contact_keys:
            raise ValueError(f"No encryption key for {sender}")
            
        cipher = Fernet(self.contact_keys[sender])
        return cipher.decrypt(b64decode(encrypted_message)).decode('utf-8')

class MessageCache:
    """Cache for messages to improve performance"""
    
    def __init__(self, max_size: int = 100):
        self.max_size = max_size
        self.messages: Dict[str, List[Dict[str, Any]]] = {}  # contact -> message list
        
    def add_message(self, contact: str, message: Dict[str, Any]) -> None:
        """Add a message to the cache"""
        if contact not in self.messages:
            self.messages[contact] = []
            
        self.messages[contact].append(message)
        
        # Trim cache if necessary
        if len(self.messages[contact]) > self.max_size:
            self.messages[contact] = self.messages[contact][-self.max_size:]
            
    def get_messages(self, contact: str) -> List[Dict[str, Any]]:
        """Get cached messages for a contact"""
        return self.messages.get(contact, [])

class BackoffStrategy:
    """Exponential backoff with jitter for reconnection attempts"""
    
    def __init__(self, initial_delay: float = 1.0, max_delay: float = 60.0, jitter: float = 0.1):
        self.initial_delay = initial_delay
        self.max_delay = max_delay
        self.jitter = jitter
        self.current_delay = initial_delay
        self.attempt = 0
        
    def get_next_delay(self) -> float:
        """Get next delay with exponential backoff and jitter"""
        self.attempt += 1
        
        # Calculate exponential backoff
        delay = min(self.initial_delay * (2 ** (self.attempt - 1)), self.max_delay)
        
        # Add jitter
        jitter_amount = delay * self.jitter
        delay = delay + random.uniform(-jitter_amount, jitter_amount)
        
        self.current_delay = delay
        return delay
        
    def reset(self) -> None:
        """Reset backoff strategy"""
        self.current_delay = self.initial_delay
        self.attempt = 0

class ChatClient:
    def __init__(self):
        self.server_url = "wss://chat.giwatech.site"
        self.websocket: Optional[websockets.WebSocketClientProtocol] = None
        self.running = True
        
        # Create history directory if it doesn't exist
        history_dir = os.path.join(os.path.expanduser("~"), ".4Chat", "history")
        os.makedirs(history_dir, exist_ok=True)
        history_file = os.path.join(history_dir, "input_history")
        
        self.prompt_session = PromptSession(history=FileHistory(history_file))
        self.username: Optional[str] = None
        self.contacts: List[str] = []
        self.online_status = {}  # Track online status of contacts
        self.auth_token: Optional[str] = None
        
        # Add components for improved functionality
        self.backoff = BackoffStrategy()
        self.encryption = E2EEncryption()
        self.message_cache = MessageCache()
        
        # Session identifier for reconnection
        self.session_id = b64encode(os.urandom(16)).decode('utf-8')
        
        # Current active chat
        self.active_chat: Optional[str] = None
        
        # Message queue for offline messages
        self.outgoing_queue = []
        
    async def connect(self):
        """Connect to the WebSocket server with TLS verification."""
        self.backoff.reset()
        
        while self.running:
            try:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[yellow]Connecting to server at {server}...[/yellow]"),
                    transient=True,
                ) as progress:
                    progress_task = progress.add_task("", server=self.server_url, total=None)
                    
                    # Create SSL context with certificate verification
                    ssl_context = ssl.create_default_context()
                    ssl_context.check_hostname = True
                    ssl_context.verify_mode = ssl.CERT_REQUIRED
                    
                    # Try to connect with a timeout
                    self.websocket = await asyncio.wait_for(
                        websockets.connect(
                            self.server_url,
                            ssl=ssl_context if self.server_url.startswith("wss") else None,
                            ping_interval=20,
                            ping_timeout=60,
                            extra_headers={"X-Session-ID": self.session_id} if self.session_id else {},
                        ),
                        timeout=10
                    )
                
                console.print("[green]Connection successful![/green]")
                return True
                
            except asyncio.TimeoutError:
                logger.error("Connection timed out")
                console.print("[red]Connection timed out. Retrying...[/red]")
                
            except Exception as e:
                logger.error(f"Connection error: {str(e)}")
                console.print(f"[red]Connection error: {str(e)}[/red]")
                
            # Wait before retrying with exponential backoff
            delay = self.backoff.get_next_delay()
            console.print(f"[yellow]Retrying in {delay:.1f} seconds...[/yellow]")
            await asyncio.sleep(delay)
            
        return False

    async def authenticate(self):
        """Handle user authentication with token support."""
        console.print(Panel.fit("[magenta]=== 4Chat ===", style="bold magenta"))
        print_ascii_art()  # Display ASCII art
        
        # Check for saved token
        token_path = os.path.join(os.path.expanduser("~"), ".4Chat", "token")
        if os.path.exists(token_path):
            try:
                with open(token_path, 'r') as f:
                    saved_token = f.read().strip()
                    token_parts = saved_token.split(':')
                    if len(token_parts) == 2:
                        username, token = token_parts
                        
                        # Try to authenticate with token
                        await self.websocket.send(json.dumps({
                            "type": "token_auth",
                            "username": username,
                            "token": token
                        }))
                        
                        response = json.loads(await self.websocket.recv())
                        if response.get("success"):
                            self.username = username
                            self.auth_token = token
                            console.print(f"\n[green][System] Welcome back, {username}![/green]")
                            return True
            except Exception as e:
                logger.error(f"Token auth error: {str(e)}")
                console.print("[yellow]Saved session expired. Please login again.[/yellow]")
        
        while True:
            try:
                # Use prompt_toolkit for input with custom style
                choice = await self.prompt_session.prompt_async(
                    HTML("<b>1.</b> Register\n<b>2.</b> Login\n<style bg='cyan'>></style> "),
                    style=prompt_style,
                    bottom_toolbar="Ctrl+C to exit",
                )
                if choice not in ("1", "2"):
                    continue

                username = await self.prompt_session.prompt_async(
                    HTML("<style fg='cyan'>Username:</style> "),
                    style=prompt_style,
                )
                password = await self.prompt_session.prompt_async(
                    HTML("<style fg='cyan'>Password:</style> "),
                    style=prompt_style,
                    is_password=True,  # Mask password input
                )

                # Reset is_password for subsequent inputs
                self.prompt_session = PromptSession(history=self.prompt_session.history)

                # Send authentication request with public key
                await self.websocket.send(json.dumps({
                    "type": "register" if choice == "1" else "login",
                    "username": username,
                    "password": password,
                    "public_key": self.encryption.get_public_key_pem(),
                    "session_id": self.session_id
                }))

                response = json.loads(await self.websocket.recv())
                if response.get("success"):
                    self.username = username
                    
                    # Save token if provided
                    if "token" in response:
                        self.auth_token = response["token"]
                        token_dir = os.path.join(os.path.expanduser("~"), ".4Chat")
                        os.makedirs(token_dir, exist_ok=True)
                        with open(os.path.join(token_dir, "token"), 'w') as f:
                            f.write(f"{username}:{self.auth_token}")
                    
                    console.print(f"\n[green][System] {response['message']}[/green]")
                    return True
                    
                console.print(f"\n[red][Error] {response['message']}[/red]")

            except (asyncio.CancelledError, KeyboardInterrupt):
                raise
            except Exception as e:
                logger.error(f"Auth error: {str(e)}")
                return False

    async def handle_input(self):
        """Handle user input with improved command handling."""
        with patch_stdout():
            while self.running:
                try:
                    # Show active chat in prompt
                    prompt_prefix = f"[{self.active_chat}] " if self.active_chat else ""
                    
                    # Use prompt_toolkit for input with custom style
                    cmd = await self.prompt_session.prompt_async(
                        HTML(f"<style fg='cyan'>{prompt_prefix}></style> "),
                        style=prompt_style,
                        bottom_toolbar=f"User: {self.username} | Type /help for commands",
                    )
                    
                    # Handle empty input
                    if not cmd.strip():
                        continue
                        
                    # Process command or message
                    if cmd.startswith("/"):
                        await self.process_command(cmd)
                    elif self.active_chat:
                        # Send message to active chat
                        await self.send_message(self.active_chat, cmd)
                    else:
                        console.print("\n[yellow]No active chat. Use /chat <user> to start chatting or /help for commands[/yellow]")

                except (KeyboardInterrupt, asyncio.CancelledError):
                    self.running = False
                    break

    async def process_command(self, cmd: str):
        """Process a command."""
        parts = cmd.split(maxsplit=1)
        command = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""
        
        if command == "/quit":
            await self.websocket.close()
            self.running = False
            
        elif command == "/clear":
            self.clear_screen()
            
        elif command == "/add":
            if not args:
                console.print("\n[red][Error] Usage: /add <username>[/red]")
                return
            await self.websocket.send(json.dumps({
                "type": "add_contact",
                "contact": args
            }))
            
        elif command == "/msg":
            msg_parts = args.split(maxsplit=1)
            if len(msg_parts) < 2:
                console.print("\n[red][Error] Usage: /msg <user> <message>[/red]")
                return
            recipient, message = msg_parts
            await self.send_message(recipient, message)
            
        elif command == "/chat":
            if not args:
                console.print("\n[red][Error] Usage: /chat <username>[/red]")
                return
                
            if args not in self.contacts:
                console.print(f"\n[red][Error] {args} is not in your contacts. Use /add {args} first.[/red]")
                return
                
            self.active_chat = args
            console.print(f"\n[green]Now chatting with {args}. Type a message to send.[/green]")
            
            # Display cached messages
            cached_messages = self.message_cache.get_messages(args)
            if cached_messages:
                console.print("\n[yellow]--- Recent Messages ---[/yellow]")
                for msg in cached_messages[-5:]:  # Show last 5 messages
                    dt = datetime.fromisoformat(msg['timestamp'])
                    timestamp = dt.strftime("%H:%M:%S")
                    
                    if console.is_terminal:
                        message_text = Text.assemble(
                            ("[", "dim"),
                            (timestamp, "blue"),
                            ("] ", "dim"),
                            (msg['from'], "green" if msg['from'] != self.username else "cyan"),
                            (": ", "dim"),
                            (msg['message'], "white")
                        )
                        console.print(message_text)
                    else:
                        console.print(f"[{timestamp}] {msg['from']}: {msg['message']}")
            
        elif command == "/contacts":
            if console.is_terminal:
                table = Table(title="Contacts", show_header=True, header_style="bold magenta")
                table.add_column("Username", style="cyan")
                table.add_column("Status", style="green")
                for contact in self.contacts:
                    status = "Online" if self.online_status.get(contact, False) else "Offline"
                    table.add_row(contact, status)
                console.print(table)
            else:
                console.print("\nContacts:")
                for contact in self.contacts:
                    status = "Online" if self.online_status.get(contact, False) else "Offline"
                    console.print(f"{contact}: {status}")
                    
        elif command == "/exit":
            if self.active_chat:
                console.print(f"\n[yellow]Exited chat with {self.active_chat}[/yellow]")
                self.active_chat = None
            else:
                console.print("\n[yellow]No active chat to exit.[/yellow]")
                
        elif command == "/help":
            console.print("\n[yellow]Commands:[/yellow]")
            console.print("[cyan]/add <username>[/cyan] - Add contact")
            console.print("[cyan]/chat <user>[/cyan] - Start chatting with a user")
            console.print("[cyan]/exit[/cyan] - Exit current chat")
            console.print("[cyan]/msg <user> <message>[/cyan] - Send one-off message")
            console.print("[cyan]/contacts[/cyan] - List contacts")
            console.print("[cyan]/clear[/cyan] - Clear the screen")
            console.print("[cyan]/quit[/cyan] - Exit application")
            
        else:
            console.print("\n[red][Error] Unknown command. Use /help[/red]")

    async def send_message(self, recipient: str, message: str):
        """Send a message with encryption."""
        try:
            if recipient not in self.contacts:
                console.print(f"\n[red][Error] {recipient} is not in your contacts.[/red]")
                return
                
            # Try to encrypt the message
            try:
                encrypted_message = self.encryption.encrypt_message(recipient, message)
            except ValueError:
                # No encryption key yet, send key exchange request
                console.print("\n[yellow]Establishing secure connection...[/yellow]")
                await self.websocket.send(json.dumps({
                    "type": "key_exchange",
                    "to": recipient,
                    "public_key": self.encryption.get_public_key_pem()
                }))
                
                # Queue message to be sent after key exchange
                self.outgoing_queue.append({
                    "to": recipient,
                    "message": message
                })
                return
                
            # Send encrypted message
            await self.websocket.send(json.dumps({
                "type": "message",
                "to": recipient,
                "message": encrypted_message,
                "encrypted": True
            }))
            
            # Cache message locally
            timestamp = datetime.now().isoformat()
            self.message_cache.add_message(recipient, {
                "from": self.username,
                "to": recipient,
                "message": message,
                "timestamp": timestamp
            })
            
            # Display in console if needed
            if self.active_chat == recipient:
                dt = datetime.fromisoformat(timestamp)
                time_str = dt.strftime("%H:%M:%S")
                
                if console.is_terminal:
                    message_text = Text.assemble(
                        ("[", "dim"),
                        (time_str, "blue"),
                        ("] ", "dim"),
                        (self.username, "cyan"),
                        (": ", "dim"),
                        (message, "white")
                    )
                    console.print(message_text)
                else:
                    console.print(f"[{time_str}] {self.username}: {message}")
                    
        except Exception as e:
            logger.error(f"Error sending message: {str(e)}")
            console.print(f"\n[red][Error] Failed to send message: {str(e)}[/red]")

    async def show_notification(self, title: str, message: str, timeout: int = 10):
        """Show a notification with a custom timeout."""
        try:
            notification.notify(
                title=title,
                message=message[:256],  # Limit message length
                app_name="4Chat",
                timeout=timeout  # Notification timeout in seconds
            )
            if platform.system() == "Linux":
                try:
                    os.system('paplay /usr/share/sounds/freedesktop/stereo/message.oga')
                except:
                    pass  # Ignore sound errors
        except Exception as e:
            logger.error(f"Notification failed: {str(e)}")

    async def handle_messages(self):
        """Handle incoming messages from the server."""
        try:
            async for message in self.websocket:
                data = json.loads(message)
                
                if data["type"] == "contact_list":
                    self.contacts = data["contacts"]
                    
                elif data["type"] == "message":
                    # Handle encrypted messages
                    dt = datetime.fromisoformat(data['timestamp'])
                    timestamp = dt.strftime("%H:%M:%S")
                    
                    sender = data['from']
                    
                    # Decrypt message if needed
                    if data.get('encrypted', False):
                        try:
                            message_text = self.encryption.decrypt_message(sender, data['message'])
                        except ValueError:
                            message_text = "[Encrypted message - encryption key not available]"
                    else:
                        message_text = data['message']
                    
                    # Cache the message
                    self.message_cache.add_message(sender, {
                        "from": sender,
                        "message": message_text,
                        "timestamp": data['timestamp']
                    })
                    
                    # Display message if it's from the active chat or no active chat
                    if not self.active_chat or self.active_chat == sender:
                        if console.is_terminal:
                            message_text_formatted = Text.assemble(
                                ("[", "dim"),
                                (timestamp, "blue"),
                                ("] ", "dim"),
                                (sender, "green"),
                                (": ", "dim"),
                                (message_text, "white")
                            )
                            console.print(message_text_formatted)
                        else:
                            console.print(f"[{timestamp}] {sender}: {message_text}")
                    
                    # Show desktop notification
                    asyncio.create_task(self.show_notification(
                        title=f"New message from {sender}",
                        message=message_text,
                        timeout=10  # 10 seconds
                    ))
                    
                elif data["type"] == "status":
                    self.online_status[data['user']] = (data['status'] == 'online')
                    console.print(f"\n[yellow][System] {data['user']} is now {data['status']}[/yellow]")
                    
                elif data["type"] == "key_exchange":
                    # Process key exchange
                    sender = data['from']
                    public_key = data['public_key']
                    
                    # Store the sender's public key
                    self.encryption.set_contact_public_key(sender, public_key)
                    
                    # Send our public key in response if not already sent
                    await self.websocket.send(json.dumps({
                        "type": "key_exchange_response",
                        "to": sender,
                        "public_key": self.encryption.get_public_key_pem()
                    }))
                    
                    console.print(f"\n[green][System] Secure connection established with {sender}[/green]")
                    
                elif data["type"] == "key_exchange_response":
                    # Process key exchange response
                    sender = data['from']
                    public_key = data['public_key']
                    
                    # Store the sender's public key
                    self.encryption.set_contact_public_key(sender, public_key)
                    
                    console.print(f"\n[green][System] Secure connection established with {sender}[/green]")
                    
                    # Send any queued messages
                    queued_messages = [msg for msg in self.outgoing_queue if msg['to'] == sender]
                    self.outgoing_queue = [msg for msg in self.outgoing_queue if msg['to'] != sender]
                    
                    for queued_msg in queued_messages:
                        await self.send_message(queued_msg['to'], queued_msg['message'])
                    
                elif data["type"] in ("system", "error"):
                    console.print(f"\n[{'yellow' if data['type'] == 'system' else 'red'}][{data['type'].title()}] {data['message']}[/{'yellow' if data['type'] == 'system' else 'red'}]")

        except ConnectionClosed:
            console.print("\n[red][System] Connection lost. Reconnecting...[/red]")
            await self.reconnect()
        except Exception as e:
            logger.error(f"Message handling error: {str(e)}")
            console.print(f"\n[red][Error] Message handling error: {str(e)}[/red]")
            await self.reconnect()

    async def reconnect(self):
        """Reconnect to the server with session resumption."""
        try:
            await self.websocket.close()
        except:
            pass
            
        if await self.connect():
            # Try to resume session with token if available
            if self.auth_token and self.username:
                await self.websocket.send(json.dumps({
                    "type": "token_auth",
                    "username": self.username,
                    "token": self.auth_token,
                    "session_id": self.session_id
                }))
                
                response = json.loads(await self.websocket.recv())
                if response.get("success"):
                    console.print("\n[green][System] Session resumed.[/green]")
                    await self.handle_messages()
                    return
                    
            # If token auth failed or no token, try regular auth
            if await self.authenticate():
                await self.handle_messages()

    def clear_screen(self):
        """Clear the terminal screen."""
        if platform.system() == "Windows":
            os.system("cls")
        else:
            os.system("clear")

    async def run(self):
        """Run the chat client."""
        try:
            if not await self.connect() or not await self.authenticate():
                return

            await asyncio.gather(
                self.handle_messages(),
                self.handle_input()
            )
        except KeyboardInterrupt:
            console.print("\n[red][System] Disconnecting...[/red]")
        except Exception as e:
            logger.error(f"Runtime error: {str(e)}")
            console.print(f"\n[red][Error] {str(e)}[/red]")
        finally:
            self.running = False
            if self.websocket:
                await self.websocket.close()

def print_ascii_art():
    """Display ASCII art for 4Chat."""
    art ="""
    
██████╗  ██████╗
██╔══██╗██╔════╝
██████╔╝██║     
██╔══██╗██║     
██████╔╝╚██████╗
╚═════╝  ╚═════╝
                                                                         
"""
    console.print(f"[bold cyan]{art}[/bold cyan]")
 
if __name__ == "__main__":
    client = ChatClient()
    asyncio.run(client.run())