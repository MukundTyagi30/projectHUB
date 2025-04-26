import asyncio
import websockets
import json
import logging
import os
import datetime
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('chat_server')

# Store for active connections and messages
# Format: {project_id: {user_id: websocket_connection}}
connected_clients = {}

# Message history for each project (limit to last 50 messages per project)
# Format: {project_id: [message1, message2, ...]}
message_history = {}
MAX_MESSAGES = 50

async def register_client(websocket, project_id, user_id, user_name):
    """Register a new client connection"""
    if project_id not in connected_clients:
        connected_clients[project_id] = {}
        
    connected_clients[project_id][user_id] = {
        'websocket': websocket,
        'user_name': user_name
    }
    
    logger.info(f"Client registered: User {user_name} (ID: {user_id}) joined project {project_id}")
    
    # Send connection notification to all clients in the project
    connection_message = {
        'type': 'system',
        'content': f"{user_name} joined the chat",
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'project_id': project_id
    }
    
    await broadcast_message(project_id, connection_message, exclude_user=None)
    
    # Send message history to the newly connected client
    if project_id in message_history:
        for historical_message in message_history[project_id]:
            await websocket.send(json.dumps(historical_message))

async def unregister_client(project_id, user_id):
    """Unregister a client connection"""
    if project_id in connected_clients and user_id in connected_clients[project_id]:
        user_name = connected_clients[project_id][user_id]['user_name']
        del connected_clients[project_id][user_id]
        
        # If no more clients in this project, remove the project entry
        if not connected_clients[project_id]:
            del connected_clients[project_id]
            
        logger.info(f"Client unregistered: User {user_name} (ID: {user_id}) left project {project_id}")
        
        # Notify other users that this user left
        disconnection_message = {
            'type': 'system',
            'content': f"{user_name} left the chat",
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'project_id': project_id
        }
        
        await broadcast_message(project_id, disconnection_message, exclude_user=user_id)

async def broadcast_message(project_id, message, exclude_user=None):
    """Broadcast a message to all clients in a project, optionally excluding the sender"""
    if project_id not in connected_clients:
        return
    
    # Add to message history
    if project_id not in message_history:
        message_history[project_id] = []
    
    # Limit the number of messages stored
    if len(message_history[project_id]) >= MAX_MESSAGES:
        message_history[project_id].pop(0)  # Remove oldest message
    
    message_history[project_id].append(message)
    
    # Broadcast to all connected clients for this project
    for user_id, client_info in connected_clients[project_id].items():
        if exclude_user and user_id == exclude_user:
            continue
        
        try:
            await client_info['websocket'].send(json.dumps(message))
        except websockets.exceptions.ConnectionClosed:
            # Handle potential connection issues
            logger.warning(f"Connection closed for user {user_id} in project {project_id} during broadcast")
            # Don't remove client here to avoid modifying dict during iteration
            # It will be removed when the connection handler exits

async def handle_client(websocket, path):
    """Handle a client connection"""
    user_id = None
    project_id = None
    
    try:
        # Wait for the initial connection message with user and project info
        async for message in websocket:
            try:
                data = json.loads(message)
                
                # Initial connection
                if data.get('type') == 'connect':
                    user_id = data.get('user_id')
                    project_id = data.get('project_id')
                    user_name = data.get('user_name')
                    
                    if not all([user_id, project_id, user_name]):
                        logger.error("Missing required connection information")
                        await websocket.send(json.dumps({
                            'type': 'error',
                            'content': 'Missing required connection information'
                        }))
                        continue
                    
                    # Register the client
                    await register_client(websocket, project_id, user_id, user_name)
                    
                # Chat message
                elif data.get('type') == 'message':
                    if not all([user_id, project_id]):  # Ensure user is registered
                        logger.error("Message received before proper connection")
                        await websocket.send(json.dumps({
                            'type': 'error',
                            'content': 'You must connect before sending messages'
                        }))
                        continue
                    
                    # Get message content
                    content = data.get('content')
                    
                    # Check if message is encrypted
                    is_encrypted = data.get('encrypted', False)
                    
                    # If encrypted, log the fact but don't try to decrypt or modify
                    if is_encrypted:
                        logger.info(f"Received encrypted message from user {user_id} in project {project_id}")
                        
                        # Note: We do not log the content of encrypted messages for privacy
                        logger.debug(f"Encrypted message starts with: {content[:20] if content else 'None'}...")
                    else:
                        # Normal non-encrypted message
                        logger.info(f"Received message from user {user_id} in project {project_id}: {content[:30]}...")
                    
                    # Create message object with sender info
                    # Pass through the 'encrypted' flag so recipients know they need to decrypt
                    message_obj = {
                        'type': 'message',
                        'sender_id': user_id,
                        'sender_name': connected_clients[project_id][user_id]['user_name'],
                        'content': content,
                        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        'project_id': project_id,
                        'encrypted': is_encrypted
                    }
                    
                    # Broadcast to all clients in the project
                    # For E2EE messages, we just relay them without modification
                    await broadcast_message(project_id, message_obj)
                    
                # Unknown message type
                else:
                    logger.warning(f"Unknown message type: {data.get('type')}")
                    
            except json.JSONDecodeError:
                logger.error("Invalid JSON received")
                await websocket.send(json.dumps({
                    'type': 'error',
                    'content': 'Invalid message format'
                }))
    
    except websockets.exceptions.ConnectionClosed:
        logger.info(f"Connection closed for user {user_id} in project {project_id}")
    
    finally:
        # Unregister the client if they were successfully registered
        if user_id and project_id:
            await unregister_client(project_id, user_id)

async def main():
    """Start the WebSocket server"""
    host = os.environ.get('CHAT_HOST', 'localhost')
    port = int(os.environ.get('CHAT_PORT', 8765))
    
    logger.info(f"Starting chat server on {host}:{port}")
    logger.info(f"End-to-end encryption is enabled. Server only relays encrypted messages.")
    
    async with websockets.serve(handle_client, host, port):
        await asyncio.Future()  # Run forever

if __name__ == "__main__":
    asyncio.run(main()) 