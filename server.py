from flask import Flask, request, jsonify, send_file
import sqlite3
import os
import socket
import subprocess
import base64
import tempfile
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from datetime import datetime

app = Flask(__name__)

# Create directory for storing uploaded files
UPLOAD_FOLDER = "uploads"
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Generate or load RSA keys
if not os.path.exists("private_key.pem"):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    public_key = private_key.public_key()
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
else:
    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    with open("public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

# Initialize users.db database
conn = sqlite3.connect("users.db")
cursor = conn.cursor()
cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        cyber_code TEXT UNIQUE NOT NULL
    )
""")
conn.commit()
conn.close()

# Initialize user_data.db database with modified messages table
# Remove the UNIQUE constraint to allow multiple messages
conn = sqlite3.connect("user_data.db")
cursor = conn.cursor()
# Drop existing table if it exists to recreate without the UNIQUE constraint
cursor.execute("DROP TABLE IF EXISTS messages")
cursor.execute("""
   CREATE TABLE IF NOT EXISTS messages (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       sender_key TEXT,
       receiver_key TEXT,
       message TEXT,
       timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
""")

# Create files table for file transfers
cursor.execute("""
   CREATE TABLE IF NOT EXISTS files (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       sender_key TEXT,
       receiver_key TEXT,
       filename TEXT,
       file_path TEXT,
       file_type TEXT,
       file_size INTEGER,
       timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
""")

# Create server_trace table
cursor.execute("""
   CREATE TABLE IF NOT EXISTS server_trace (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       requester_key TEXT,
       target_host TEXT,
       trace_result TEXT,
       timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
""")

conn.commit()
conn.close()

#get public key
@app.route("/get_public_key", methods=["GET"])
def get_public_key():
    """Send the public key to clients."""
    with open("public_key.pem", "rb") as f:
        public_key_data = f.read()
    return jsonify({"public_key": public_key_data.decode()})

#register
@app.route("/register", methods=["POST"])
def register():
    """Register a new user with encrypted password and generate a Cyber Code."""
    data = request.json
    username = data.get("username")
    encrypted_password = data.get("password")

    if not username or not encrypted_password:
        return jsonify({"error": "Missing username or password"}), 400

    # Generate a unique Cyber Code
    cyber_code = os.urandom(16).hex()

    try:
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password, cyber_code) VALUES (?, ?, ?)",
                       (username, encrypted_password, cyber_code))
        conn.commit()
        conn.close()
        return jsonify({"message": "User registered successfully", "cyber_code": cyber_code})
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409

#login
@app.route("/login", methods=["POST"])
def login():
    """Authenticate user and return their Cyber Code if credentials match."""
    data = request.json
    username = data.get("username")
    encrypted_password = data.get("password")

    if not username or not encrypted_password:
        return jsonify({"error": "Missing username or password"}), 400

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password, cyber_code FROM users WHERE username = ?", (username,))
    user_data = cursor.fetchone()
    conn.close()

    if not user_data:
        return jsonify({"error": "User not found"}), 404

    stored_encrypted_password, cyber_code = user_data

    # Decrypt the received password using the private key
    try:
        decrypted_received_password = private_key.decrypt(
            bytes.fromhex(encrypted_password),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()

        decrypted_stored_password = private_key.decrypt(
            bytes.fromhex(stored_encrypted_password),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()

        if decrypted_received_password == decrypted_stored_password:
            return jsonify({"message": "Login successful", "cyber_code": cyber_code})
        else:
            return jsonify({"error": "Invalid password"}), 401
    except:
        return jsonify({"error": "Invalid authentication"}), 401

#send
@app.route("/send_data", methods=["POST"])
def send_data():
    """Store a new message with sender and receiver information."""
    data = request.json
    sender_key = data.get("sender_key")
    receiver_key = data.get("receiver_key")
    message = data.get("message")

    if not sender_key or not receiver_key or not message:
        return jsonify({"error": "Missing sender, receiver, or message"}), 400

    try:
        conn = sqlite3.connect("user_data.db")
        cursor = conn.cursor()
        
        # Insert a new message record each time
        cursor.execute("""
            INSERT INTO messages (sender_key, receiver_key, message)
            VALUES (?, ?, ?)
        """, (sender_key, receiver_key, message))

        conn.commit()
        conn.close()

        return jsonify({"message": "Message sent successfully!"})
    except Exception as e:
        return jsonify({"error": f"Failed to send message: {str(e)}"}), 500

@app.route("/receive_data", methods=["POST"])
def receive_data():
    """Retrieve all messages for the receiver with new message tracking."""
    data = request.json
    receiver_key = data.get("receiver_key")
    last_message_id = data.get("last_message_id", 0)  # Default to 0 if not provided

    if not receiver_key:
        return jsonify({"error": "Missing receiver key"}), 400

    try:
        conn = sqlite3.connect("user_data.db")
        cursor = conn.cursor()
        
        # Only get messages newer than the last seen message ID
        cursor.execute("""
            SELECT id, sender_key, message FROM messages 
            WHERE receiver_key = ? AND id > ?
            ORDER BY id ASC
        """, (receiver_key, last_message_id))
        
        results = cursor.fetchall()
        conn.close()

        if not results:
            return jsonify({"messages": [], "last_message_id": last_message_id}), 200

        # Include message ID with each message for tracking
        messages = [{"id": msg_id, "sender": sender, "message": message} 
                   for msg_id, sender, message in results]
        
        # Return the highest message ID for future tracking
        new_last_id = max(msg["id"] for msg in messages)

        return jsonify({"messages": messages, "last_message_id": new_last_id}), 200
    
    except Exception as e:
        return jsonify({"error": f"Failed to retrieve messages: {str(e)}"}), 500

@app.route("/transfer_file", methods=["POST"])
def transfer_file():
    """Handle file transfer between users."""
    try:
        # Extract file data and metadata
        sender_key = request.form.get("sender_key")
        receiver_key = request.form.get("receiver_key")
        file_data_b64 = request.form.get("file_data")
        filename = request.form.get("filename")
        file_type = request.form.get("file_type")
        
        if not all([sender_key, receiver_key, file_data_b64, filename, file_type]):
            return jsonify({"error": "Missing required file transfer parameters"}), 400
            
        # Check for valid file type (security measure)
        allowed_types = ['.txt', '.png', '.jpg', '.jpeg', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip']
        file_extension = os.path.splitext(filename)[1].lower()
        if file_extension not in allowed_types:
            return jsonify({"error": f"File type {file_extension} not allowed"}), 400
            
        # Create unique filename to prevent overwrites
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        unique_filename = f"{timestamp}_{filename}"
        file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
        
        # Decode and save the file
        file_data = base64.b64decode(file_data_b64)
        file_size = len(file_data)
        
        with open(file_path, 'wb') as f:
            f.write(file_data)
            
        # Record the file transfer in database
        conn = sqlite3.connect("user_data.db")
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO files (sender_key, receiver_key, filename, file_path, file_type, file_size)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (sender_key, receiver_key, filename, file_path, file_type, file_size))
        
        file_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return jsonify({
            "message": "File transferred successfully",
            "file_id": file_id,
            "file_size": file_size
        })
        
    except Exception as e:
        return jsonify({"error": f"File transfer failed: {str(e)}"}), 500

@app.route("/list_files", methods=["POST"])
def list_files():
    """List all files available for download by the receiver."""
    receiver_key = request.json.get("receiver_key")
    
    if not receiver_key:
        return jsonify({"error": "Missing receiver key"}), 400
        
    try:
        conn = sqlite3.connect("user_data.db")
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, sender_key, filename, file_type, file_size, timestamp
            FROM files
            WHERE receiver_key = ?
            ORDER BY timestamp DESC
        """, (receiver_key,))
        
        results = cursor.fetchall()
        conn.close()
        
        if not results:
            return jsonify({"files": []}), 200
            
        files = [{
            "id": file_id,
            "sender": sender,
            "filename": filename,
            "type": file_type,
            "size": file_size,
            "timestamp": timestamp
        } for file_id, sender, filename, file_type, file_size, timestamp in results]
        
        return jsonify({"files": files}), 200
        
    except Exception as e:
        return jsonify({"error": f"Failed to list files: {str(e)}"}), 500

@app.route("/download_file/<int:file_id>", methods=["GET"])
def download_file(file_id):
    """Download a file by its ID."""
    requester_key = request.args.get("requester_key")
    
    if not requester_key:
        return jsonify({"error": "Missing requester key"}), 400
        
    try:
        conn = sqlite3.connect("user_data.db")
        cursor = conn.cursor()
        cursor.execute("""
            SELECT file_path, filename, receiver_key
            FROM files
            WHERE id = ?
        """, (file_id,))
        
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return jsonify({"error": "File not found"}), 404
            
        file_path, filename, receiver_key = result
        
        # Security check: only the intended receiver can download the file
        if requester_key != receiver_key:
            return jsonify({"error": "Unauthorized to download this file"}), 403
            
        # Check if file exists
        if not os.path.exists(file_path):
            return jsonify({"error": "File no longer available"}), 404
            
        return send_file(file_path, as_attachment=True, download_name=filename)
        
    except Exception as e:
        return jsonify({"error": f"Failed to download file: {str(e)}"}), 500

@app.route("/server_trace", methods=["POST"])
def server_trace():
    """Perform DNS lookup and network trace on target host."""
    requester_key = request.json.get("requester_key")
    target_host = request.json.get("target_host")
    
    if not requester_key or not target_host:
        return jsonify({"error": "Missing requester key or target host"}), 400
    
    try:
        # Basic security check: make sure target_host is a valid hostname
        # Avoid command injection by rejecting hosts with shell special characters
        if any(c in target_host for c in ['&', '|', ';', '$', '`', '>', '<', '*', '?', '!']):
            return jsonify({"error": "Invalid hostname"}), 400
        
        result = {"dns_info": {}, "trace_info": {}}
        
        # DNS lookup
        try:
            ip_address = socket.gethostbyname(target_host)
            result["dns_info"]["ip_address"] = ip_address
            
            # Reverse DNS lookup
            try:
                hostname, _, _ = socket.gethostbyaddr(ip_address)
                result["dns_info"]["hostname"] = hostname
            except socket.herror:
                result["dns_info"]["hostname"] = "Reverse lookup failed"
        except socket.gaierror:
            result["dns_info"]["error"] = "DNS resolution failed"
        
        # Traceroute (platform-specific)
        if os.name == "nt":  # Windows
            trace_cmd = ["tracert", "-d", "-w", "1000", "-h", "15", target_host]
        else:  # Linux/Mac
            trace_cmd = ["traceroute", "-n", "-w", "1", "-m", "15", target_host]
            
        try:
            trace_output = subprocess.run(
                trace_cmd, 
                capture_output=True, 
                text=True, 
                timeout=30
            )
            result["trace_info"]["output"] = trace_output.stdout
            if trace_output.stderr:
                result["trace_info"]["error"] = trace_output.stderr
        except subprocess.TimeoutExpired:
            result["trace_info"]["error"] = "Trace timed out"
        except subprocess.SubprocessError as e:
            result["trace_info"]["error"] = f"Trace error: {str(e)}"
        
        # Store the trace results in the database
        conn = sqlite3.connect("user_data.db")
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO server_trace (requester_key, target_host, trace_result)
            VALUES (?, ?, ?)
        """, (requester_key, target_host, str(result)))
        trace_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        # Return the results to the client
        return jsonify({
            "trace_id": trace_id,
            "target_host": target_host,
            "result": result
        }), 200
        
    except Exception as e:
        return jsonify({"error": f"Server trace failed: {str(e)}"}), 500
    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
