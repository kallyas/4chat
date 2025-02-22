import asyncio
import websockets
import json
import logging
from datetime import datetime
from typing import Optional, List
from websockets.exceptions import ConnectionClosed
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
from plyer import notification
import os


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ChatClient:
    def __init__(self, server_url: str = "wss://chat.giwatech.site"):
        self.server_url = server_url
        self.websocket: Optional[websockets.WebSocketClientProtocol] = None
        self.running = True
        self.prompt_session = PromptSession()
        self.username: Optional[str] = None
        self.contacts: List[str] = []

    async def connect(self):
        retry_delay = 1
        while self.running:
            try:
                self.websocket = await websockets.connect(
                    self.server_url, ping_interval=20, ping_timeout=60
                )
                return True
            except Exception as e:
                logger.error(f"Connection error: {str(e)}")
                await asyncio.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, 30)
        return False

    async def authenticate(self):
        print("\n=== SecureChat ===")
        while True:
            try:
                choice = await self.prompt_session.prompt_async(
                    "1. Register\n2. Login\n> ", bottom_toolbar="Ctrl+C to exit"
                )
                if choice not in ("1", "2"):
                    continue

                username = await self.prompt_session.prompt_async("Username: ")
                password = await self.prompt_session.prompt_async("Password: ", is_password=False)

                await self.websocket.send(json.dumps({
                    "type": "register" if choice == "1" else "login",
                    "username": username,
                    "password": password
                }))

                response = json.loads(await self.websocket.recv())
                if response.get("success"):
                    self.username = username
                    print(f"\n[System] {response['message']}")
                    return True
                print(f"\n[Error] {response['message']}")

            except (asyncio.CancelledError, KeyboardInterrupt):
                raise
            except Exception as e:
                logger.error(f"Auth error: {str(e)}")
                return False

    async def handle_input(self):
        with patch_stdout():
            while self.running:
                try:
                    cmd = await self.prompt_session.prompt_async(
                        "> ", bottom_toolbar=f"User: {self.username}"
                    )
                    if cmd == "/quit":
                        await self.websocket.close()
                        self.running = False
                        break
                    elif cmd.startswith("/add "):
                        contact = cmd.split(maxsplit=1)[1]
                        await self.websocket.send(json.dumps({
                            "type": "add_contact",
                            "contact": contact
                        }))
                    elif cmd.startswith("/msg "):
                        parts = cmd.split(maxsplit=2)
                        if len(parts) < 3:
                            print("\n[Error] Usage: /msg <user> <message>")
                            continue
                        _, recipient, message = parts
                        await self.websocket.send(json.dumps({
                            "type": "message",
                            "to": recipient,
                            "message": message
                        }))
                    elif cmd == "/contacts":
                        print(f"\n[Contacts] {', '.join(self.contacts) or 'No contacts'}")
                    elif cmd == "/help":
                        print("\nCommands:")
                        print("/add <username> - Add contact")
                        print("/msg <user> <message> - Send message")
                        print("/contacts - List contacts")
                        print("/quit - Exit")
                    else:
                        print("\n[Error] Unknown command. Use /help")

                except (KeyboardInterrupt, asyncio.CancelledError):
                    self.running = False
                    break

    async def handle_messages(self):
        try:
            async for message in self.websocket:
                data = json.loads(message)
                if data["type"] == "contact_list":
                    self.contacts = data["contacts"]
                elif data["type"] == "message":
                    dt = datetime.fromisoformat(data['timestamp'])
                    timestamp = dt.strftime("%H:%M:%S")
                    message_text = f"[{timestamp}] {data['from']}: {data['message']}"
                    
                    # Show desktop notification
                    try:
                        notification.notify(
                            title=f"New message from {data['from']}",
                            message=data['message'][:256],  # Limit message length
                            app_name="SecureChat",
                            timeout=5  # Seconds to show notification
                            
                        )
                        os.system('paplay /usr/share/sounds/freedesktop/stereo/message.oga')
                    except Exception as e:
                        logger.error(f"Notification failed: {str(e)}")
                    
                    print(f"\n{message_text}")
                elif data["type"] in ("system", "error"):
                    print(f"\n[{data['type'].title()}] {data['message']}")

        except ConnectionClosed:
            print("\n[System] Connection lost. Reconnecting...")
            await self.reconnect()
    async def reconnect(self):
        await self.websocket.close()
        if await self.connect() and await self.authenticate():
            await self.handle_messages()

    async def run(self):
        try:
            if not await self.connect() or not await self.authenticate():
                return

            await asyncio.gather(
                self.handle_messages(),
                self.handle_input()
            )
        except KeyboardInterrupt:
            print("\n[System] Disconnecting...")
        finally:
            self.running = False
            if self.websocket:
                await self.websocket.close()

if __name__ == "__main__":
    client = ChatClient()
    asyncio.run(client.run())