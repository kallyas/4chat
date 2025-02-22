import asyncio
import websockets
import json
import sqlite3
import bcrypt # type: ignore
from datetime import datetime

# Database setup
conn = sqlite3.connect('chat.db', check_same_thread=False)
c = conn.cursor()

# Create tables
c.execute('''CREATE TABLE IF NOT EXISTS users
             (id INTEGER PRIMARY KEY, 
              username TEXT UNIQUE, 
              password_hash TEXT)''')

c.execute('''CREATE TABLE IF NOT EXISTS contacts
             (user_id INTEGER,
              contact_id INTEGER,
              FOREIGN KEY(user_id) REFERENCES users(id),
              FOREIGN KEY(contact_id) REFERENCES users(id),
              UNIQUE(user_id, contact_id))''')

c.execute('''CREATE TABLE IF NOT EXISTS messages
             (id INTEGER PRIMARY KEY,
              sender_id INTEGER,
              receiver_id INTEGER,
              message TEXT,
              timestamp DATETIME,
              delivered BOOLEAN DEFAULT 0)''')
conn.commit()

class ChatServer:
    def __init__(self):
        self.connections = {}
        self.user_contacts = {}

    async def handle_auth(self, websocket, data):
        """Handle user authentication."""
        try:
            if data['type'] == 'register':
                if c.execute("SELECT 1 FROM users WHERE username = ?", 
                            (data['username'],)).fetchone():
                    return {'success': False, 'message': 'Username taken'}
                
                hashed = bcrypt.hashpw(data['password'].encode(), bcrypt.gensalt())
                c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                         (data['username'], hashed.decode('utf-8')))
                conn.commit()
                return {'success': True, 'message': 'Registration successful'}
                
            elif data['type'] == 'login':
                user = c.execute("SELECT id, password_hash FROM users WHERE username = ?", 
                                (data['username'],)).fetchone()
                if not user:
                    return {'success': False, 'message': 'Invalid credentials'}
                
                hashed_password = user[1].encode('utf-8')
                if not bcrypt.checkpw(data['password'].encode(), hashed_password):
                    return {'success': False, 'message': 'Invalid credentials'}
                
                # Load contacts and undelivered messages
                contacts = c.execute('''SELECT u.username 
                                      FROM contacts c
                                      JOIN users u ON c.contact_id = u.id
                                      WHERE c.user_id = ?''', (user[0],)).fetchall()
                self.user_contacts[data['username']] = [c[0] for c in contacts]
                
                # Send pending messages
                pending = c.execute('''SELECT m.message, u.username, m.timestamp
                                     FROM messages m
                                     JOIN users u ON m.sender_id = u.id
                                     WHERE m.receiver_id = ? AND m.delivered = 0''', (user[0],)).fetchall()
                for msg in pending:
                    await websocket.send(json.dumps({
                        'type': 'message',
                        'from': msg[1],
                        'message': msg[0],
                        'timestamp': msg[2]
                    }))
                    c.execute("UPDATE messages SET delivered = 1 WHERE rowid = ?", (msg[0],))
                conn.commit()
                
                return {'success': True, 'message': 'Login successful'}

        except Exception as e:
            return {'success': False, 'message': str(e)}

    async def handle_connection(self, websocket):
        """Handle a new WebSocket connection."""
        username = None
        try:
            auth_data = json.loads(await websocket.recv())
            auth_result = await self.handle_auth(websocket, auth_data)
            await websocket.send(json.dumps(auth_result))
            
            if not auth_result.get('success'):
                await websocket.close()
                return

            username = auth_data['username']
            self.connections[username] = websocket

            await websocket.send(json.dumps({
                'type': 'contact_list',
                'contacts': self.user_contacts.get(username, [])
            }))

            async for message in websocket:
                data = json.loads(message)
                if data['type'] == 'add_contact':
                    await self.add_contact(username, data['contact'])
                elif data['type'] == 'remove_contact':
                    await self.remove_contact(username, data['contact'])
                elif data['type'] == 'message':
                    await self.route_message(username, data)

        except websockets.ConnectionClosed:
            print(f"{username} disconnected")
        finally:
            if username and username in self.connections:
                del self.connections[username]

    async def add_contact(self, username, contact):
        """Add a contact with mutual check."""
        try:
            contact_user = c.execute("SELECT id FROM users WHERE username = ?", 
                                   (contact,)).fetchone()
            if not contact_user:
                await self.connections[username].send(json.dumps({
                    'type': 'error',
                    'message': f'User {contact} does not exist'
                }))
                return

            user_id = c.execute("SELECT id FROM users WHERE username = ?", 
                                (username,)).fetchone()[0]
            contact_id = contact_user[0]

            if c.execute("SELECT 1 FROM contacts WHERE user_id = ? AND contact_id = ?",
                        (user_id, contact_id)).fetchone():
                await self.connections[username].send(json.dumps({
                    'type': 'error',
                    'message': f'{contact} is already in your contacts'
                }))
                return

            c.execute("INSERT INTO contacts (user_id, contact_id) VALUES (?, ?)",
                     (user_id, contact_id))
            conn.commit()
            
            self.user_contacts[username].append(contact)
            await self.update_contact_list(username)
            
            # Notify both users if mutual contact
            if c.execute("SELECT 1 FROM contacts WHERE user_id = ? AND contact_id = ?",
                        (contact_id, user_id)).fetchone():
                notification = f'You are now mutual contacts with {contact}'
                await self.connections[username].send(json.dumps({
                    'type': 'system',
                    'message': notification
                }))
                if contact in self.connections:
                    await self.connections[contact].send(json.dumps({
                        'type': 'system',
                        'message': f'You are now mutual contacts with {username}'
                    }))

        except Exception as e:
            await self.connections[username].send(json.dumps({
                'type': 'error',
                'message': str(e)
            }))

    async def route_message(self, sender, data):
        """Route messages with mutual contact verification."""
        try:
            sender_id = c.execute("SELECT id FROM users WHERE username = ?", 
                                (sender,)).fetchone()[0]
            receiver = data['to']
            
            # Check receiver existence
            receiver_row = c.execute("SELECT id FROM users WHERE username = ?", 
                                   (receiver,)).fetchone()
            if not receiver_row:
                await self.connections[sender].send(json.dumps({
                    'type': 'error',
                    'message': f"User {receiver} does not exist"
                }))
                return
            receiver_id = receiver_row[0]

            # Check mutual contacts
            sender_to_receiver = c.execute("SELECT 1 FROM contacts WHERE user_id = ? AND contact_id = ?",
                              (sender_id, receiver_id)).fetchone()
            receiver_to_sender = c.execute("SELECT 1 FROM contacts WHERE user_id = ? AND contact_id = ?",
                              (receiver_id, sender_id)).fetchone()
            if not (sender_to_receiver and receiver_to_sender):
                await self.connections[sender].send(json.dumps({
                    'type': 'error',
                    'message': f"You can only message mutual contacts. {receiver} needs to add you back."
                }))
                return

            # Store message with timestamp
            timestamp = datetime.now().isoformat()
            c.execute('''INSERT INTO messages 
                        (sender_id, receiver_id, message, timestamp)
                        VALUES (?, ?, ?, ?)''',
                     (sender_id, receiver_id, data['message'], timestamp))
            conn.commit()

            # Deliver message if online
            if receiver in self.connections:
                await self.connections[receiver].send(json.dumps({
                    'type': 'message',
                    'from': sender,
                    'message': data['message'],
                    'timestamp': timestamp
                }))
                c.execute("UPDATE messages SET delivered = 1 WHERE rowid = ?", 
                         (c.lastrowid,))
                conn.commit()
            else:
                await self.connections[sender].send(json.dumps({
                    'type': 'system',
                    'message': f"{receiver} is offline. Message will be delivered when they're back."
                }))

        except Exception as e:
            print(f"Message routing error: {str(e)}")
            await self.connections[sender].send(json.dumps({
                'type': 'error',
                'message': 'Failed to send message'
            }))

    async def update_contact_list(self, username):
        """Update user's contact list."""
        contacts = self.user_contacts.get(username, [])
        await self.connections[username].send(json.dumps({
            'type': 'contact_list',
            'contacts': contacts
        }))

async def main():
    server = ChatServer()
    # Add explicit startup message
    print("Starting server on ws://localhost:8765")
    async with websockets.serve(server.handle_connection, "localhost", 8765) as server:
        # Add server status confirmation
        print(f"Server successfully started! Listening on {server.sockets[0].getsockname()}")
        await asyncio.Future()  # Keep server running
asyncio.run(main())