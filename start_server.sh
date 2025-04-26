#!/bin/bash

echo "Starting ProjectHub application..."

# Define directories
BACKEND_DIR="backend"
SSL_DIR="$BACKEND_DIR/ssl"

# Create SSL directory if it doesn't exist
mkdir -p $SSL_DIR

# Check for SSL certificates and generate if needed
if [ ! -f "$SSL_DIR/cert.pem" ] || [ ! -f "$SSL_DIR/key.pem" ]; then
    echo "Generating self-signed SSL certificates..."
    openssl req -x509 -newkey rsa:4096 -nodes -out $SSL_DIR/cert.pem -keyout $SSL_DIR/key.pem -days 365 \
        -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
    echo "SSL certificates generated successfully."
fi

# Start Flask server
echo "Starting Flask server..."
cd $BACKEND_DIR

# Activate Flask virtual environment
if [ -d "flask_venv" ]; then
    source flask_venv/bin/activate
else
    python3 -m venv flask_venv
    source flask_venv/bin/activate
    pip install flask flask-sqlalchemy flask-cors pyjwt flask-jwt-extended werkzeug bcrypt python-dotenv
fi

# Set environment variables
export FLASK_APP=app.py
export FLASK_ENV=development
export FLASK_PORT=5001
export FLASK_HOST=127.0.0.1
export SSL_ENABLED=true

# Run app.py directly instead of using flask run to ensure SSL works
python app.py &
FLASK_PID=$!
echo "Flask server started with PID: $FLASK_PID"

# Start WebSocket server
echo "Starting WebSocket server..."

# Activate WebSocket virtual environment
if [ -d "chat_venv" ]; then
    source chat_venv/bin/activate
else
    python3 -m venv chat_venv
    source chat_venv/bin/activate
    pip install websockets
fi

export CHAT_HOST=127.0.0.1
export CHAT_PORT=8765
python chat_server.py &
CHAT_PID=$!
echo "WebSocket server started with PID: $CHAT_PID"

# Function to handle script termination
cleanup() {
    echo "Shutting down servers..."
    kill $FLASK_PID $CHAT_PID
    echo "Servers stopped."
    exit 0
}

# Set up trap for cleanup on termination
trap cleanup SIGINT SIGTERM

# Keep script running
echo "Both servers are running. Press Ctrl+C to stop."
echo "Access the application at: https://127.0.0.1:5001"
echo "Warning: Since this is using a self-signed certificate, you will need to accept the security warning in your browser."
echo "WebSocket server running at: ws://127.0.0.1:8765"

# Wait for user to press Ctrl+C
while true; do
    sleep 1
done 