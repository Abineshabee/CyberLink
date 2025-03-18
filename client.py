import requests
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
import base64
import time
import os
import json
from datetime import datetime
import pwinput

# Fetch public key from server
response = requests.get("http://127.0.0.1:5000/get_public_key")
if response.status_code != 200:
    print("Error fetching public key from server.")
    exit(1)

public_key_pem = response.json()["public_key"]
public_key = serialization.load_pem_public_key(public_key_pem.encode())

def encrypt_password(password):
    """Encrypt password using the server's public key."""
    encrypted = public_key.encrypt(
        password.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted.hex()

def register(username, password):
    """Register a new user by sending encrypted credentials to the server."""
    encrypted_password = encrypt_password(password)
    
    data = {
        "username": username,
        "password": encrypted_password
    }
    
    response = requests.post("http://127.0.0.1:5000/register", json=data)
    
    if response.status_code == 200:
        print(f"User registered successfully! Cyber Code: {response.json()['cyber_code']}")
    else:
        print(f"Error: {response.json()['error']}")

def login(username, password):
    """Login user by verifying encrypted credentials."""
    encrypted_password = encrypt_password(password)
    
    data = {
        "username": username,
        "password": encrypted_password
    }
    
    response = requests.post("http://127.0.0.1:5000/login", json=data)
    
    if response.status_code == 200:
        cyber_code = response.json()['cyber_code']
        print("\nLogin successful!\n")
        
        print( "╔═════════════════════════════════════════════════════╗")
        print(f"║  Cyber Code :  [ {cyber_code} ] ║ ")
        print( "╚═════════════════════════════════════════════════════╝\n")
        
        
        return cyber_code
    else:
        print(f"Error: {response.json()['error']}")
        return None

def send_data(sender_code, receiver_code, message):
    """Send a message to another user."""
    if not receiver_code.strip():  # Ensure receiver_code is not empty
        print("Error: Receiver code cannot be empty.")
        return
        
    receiver_key = get_fixed_key(receiver_code)
    encrypted_data = encrypt_data(message, receiver_key)
    
    data = {
        "sender_key": sender_code,
        "receiver_key": receiver_code,
        "message": encrypted_data.decode() 
    }
    
    response = requests.post("http://127.0.0.1:5000/send_data", json=data)
    
    if response.status_code == 200:
        print("Message sent successfully!")
    else:
        print(f"Error: {response.json()['error']}")

def receive_data(user_code):
    """Continuously check for new messages."""
    print("Waiting for new messages... (Press Ctrl+C to stop)")
    
    last_message_id = 0  # Track the last seen message ID
    temp = 1

    try:
        while True:
            data = {
                "receiver_key": user_code,
                "last_message_id": last_message_id
            }
            
            response = requests.post("http://127.0.0.1:5000/receive_data", json=data)

            if response.status_code == 200:
                try:
                    response_json = response.json()
                    
                    # Update the last message ID from the response
                    if "last_message_id" in response_json:
                        last_message_id = response_json["last_message_id"]
                    
                    # Process new messages
                    if "messages" in response_json and response_json["messages"]:
                        for msg in response_json["messages"]:
                            sender = msg["sender"]
                            encrypted_msg = msg["message"]

                            if isinstance(encrypted_msg, str):
                                encrypted_msg = encrypted_msg.encode()  # Ensure it's bytes

                            user_key = get_fixed_key(user_code)
                            decrypted_data = decrypt_data(encrypted_msg, user_key)
                            
                            print(f"New Message Received From {sender}: {decrypted_data}")
                                 
                except ValueError as e:
                    print(f"Error parsing response: {e}")
            else:
                print(f"Server error: {response.status_code} - {response.text}")

            time.sleep(2)  # Check for messages every 2 seconds
    except KeyboardInterrupt:
        print("\nStopped listening for messages.")
        
def get_fixed_key(hex_key):
    """Ensures the key is 32 bytes before Base64 encoding."""
    key_bytes = bytes.fromhex(hex_key)  # Convert hex string to raw bytes

    # Ensure the key is exactly 32 bytes (pad or trim if necessary)
    key_bytes = key_bytes.ljust(32, b'\0')[:32]  

    base64_key = base64.urlsafe_b64encode(key_bytes)  # Convert bytes to Base64
    return base64_key
 
def encrypt_data(data, key):
    """Encrypts data using the provided key."""
    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode())
    return encrypted_data

def decrypt_data(encrypted_data, key):
    """Decrypts data using the provided key."""
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data).decode()
    return decrypted_data

def transfer_file(sender_code, receiver_code, file_path):
    """Transfer a file to another user."""
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found.")
        return
        
    if not receiver_code.strip():
        print("Error: Receiver code cannot be empty.")
        return
        
    # Get file info
    filename = os.path.basename(file_path)
    file_ext = os.path.splitext(filename)[1].lower()
    
    # Check if file type is allowed
    allowed_types = ['.txt', '.png', '.jpg', '.jpeg', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip']
    if file_ext not in allowed_types:
        print(f"Error: File type '{file_ext}' not allowed. Allowed types: {', '.join(allowed_types)}")
        return
        
    # Read file data
    try:
        with open(file_path, 'rb') as f:
            file_data = f.read()
            
        # Encode file data in base64
        file_data_b64 = base64.b64encode(file_data).decode()
        
        # Create form data
        form_data = {
            "sender_key": sender_code,
            "receiver_key": receiver_code,
            "filename": filename,
            "file_type": file_ext,
            "file_data": file_data_b64
        }
        
        print(f"Transferring file '{filename}' ({len(file_data)/1024:.2f} KB)...")
        
        # Send the file
        response = requests.post("http://127.0.0.1:5000/transfer_file", data=form_data)
        
        if response.status_code == 200:
            file_id = response.json().get("file_id")
            file_size = response.json().get("file_size", 0)
            print(f"File transferred successfully! ID: {file_id}, Size: {file_size/1024:.2f} KB")
        else:
            print(f"Error: {response.json().get('error', 'Unknown error')}")
            
    except Exception as e:
        print(f"File transfer failed: {str(e)}")

def list_files(user_code):
    """List all files available for download."""
    try:
        data = {"receiver_key": user_code}
        response = requests.post("http://127.0.0.1:5000/list_files", json=data)
        
        if response.status_code == 200:
            files = response.json().get("files", [])
            
            if not files:
                print("No files available.")
                return []
                
            print("\nAvailable Files:")
            print("----------------")
            for i, file in enumerate(files, 1):
                size_kb = file.get("size", 0) / 1024
                timestamp = file.get("timestamp", "Unknown")
                print(f"{i}. ID: {file['id']} | From: {file['sender']} | {file['filename']} | {size_kb:.2f} KB | {timestamp}")
                
            return files
        else:
            print(f"Error listing files: {response.json().get('error', 'Unknown error')}")
            return []
            
    except Exception as e:
        print(f"Failed to list files: {str(e)}")
        return []

def download_file(user_code, file_id, save_dir="."):
    """Download a file by its ID."""
    try:
        if not os.path.exists(save_dir):
            os.makedirs(save_dir)
            
        print(f"Downloading file {file_id}...")
        
        # Get the file
        response = requests.get(
            f"http://127.0.0.1:5000/download_file/{file_id}",
            params={"requester_key": user_code},
            stream=True
        )
        
        if response.status_code == 200:
            # Get filename from content-disposition header
            content_disposition = response.headers.get('content-disposition', '')
            filename = "downloaded_file"
            
            if 'filename=' in content_disposition:
                filename = content_disposition.split('filename=')[1].strip('"')
                
            save_path = os.path.join(save_dir, filename)
            
            # Save the file
            with open(save_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
                    
            print(f"File downloaded successfully and saved to: {save_path}")
            return save_path
        else:
            error_msg = "Unknown error"
            try:
                error_msg = response.json().get("error", error_msg)
            except:
                pass
            print(f"Error downloading file: {error_msg}")
            return None
            
    except Exception as e:
        print(f"Failed to download file: {str(e)}")
        return None

def server_trace(user_code, target_host):
    """Perform a network trace to the target host."""
    if not target_host or not target_host.strip():
        print("Error: Target host cannot be empty.")
        return
        
    print(f"Tracing route to {target_host}...")
    
    try:
        data = {
            "requester_key": user_code,
            "target_host": target_host.strip()
        }
        
        response = requests.post("http://127.0.0.1:5000/server_trace", json=data)
        
        if response.status_code == 200:
            result = response.json()
            trace_id = result.get("trace_id")
            trace_result = result.get("result", {})
            
            print(f"\nTrace ID: {trace_id}")
            print(f"Target Host: {target_host}")
            
            # Print DNS information
            dns_info = trace_result.get("dns_info", {})
            print("\nDNS Information:")
            print("-----------------")
            if "error" in dns_info:
                print(f"Error: {dns_info['error']}")
            else:
                print(f"IP Address: {dns_info.get('ip_address', 'Not available')}")
                print(f"Hostname: {dns_info.get('hostname', 'Not available')}")
                
            # Print trace information
            trace_info = trace_result.get("trace_info", {})
            print("\nTrace Information:")
            print("------------------")
            if "error" in trace_info:
                print(f"Error: {trace_info['error']}")
            else:
                trace_output = trace_info.get("output", "")
                print(trace_output)
                
            # Save trace to file
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            trace_filename = f"trace_{target_host}_{timestamp}.txt"
            
            with open(trace_filename, "w") as f:
                f.write(f"Trace ID: {trace_id}\n")
                f.write(f"Target Host: {target_host}\n\n")
                f.write("DNS Information:\n")
                f.write("-----------------\n")
                if "error" in dns_info:
                    f.write(f"Error: {dns_info['error']}\n")
                else:
                    f.write(f"IP Address: {dns_info.get('ip_address', 'Not available')}\n")
                    f.write(f"Hostname: {dns_info.get('hostname', 'Not available')}\n")
                    
                f.write("\nTrace Information:\n")
                f.write("------------------\n")
                if "error" in trace_info:
                    f.write(f"Error: {trace_info['error']}\n")
                else:
                    f.write(trace_output)
                    
            print(f"\nTrace saved to file: {trace_filename}")
            
        else:
            print(f"Error: {response.json().get('error', 'Unknown error')}")
            
    except Exception as e:
        print(f"Server trace failed: {str(e)}")

if __name__ == "__main__":

    banner = """
╔═══╤══════════════════════════════════╗
║ # │   Welcome to CyberLink -v 0.1    ║
╟───┼──────────────────────────────────╢
║ 1 │ Register                         ║
║ 2 │ Login                            ║
║ 3 │ Exit                             ║
╚═══╧══════════════════════════════════╝
    """
    banner2 = """
╔══════════════════════════════╗
║    Registered Successfully   ║
╚══════════════════════════════╝
    """
    
    print(banner)
    choice = input(" >> ")
    
    if choice == "1":
        
        print( 10*"_" , "Registeration For New User" , 10*"_")
        username = input("\nCyberLink Username > ")
        password = pwinput.pwinput("CyberLink Password > ", mask="*")   
        print( 48 *"_")
        
        #register(username, password) #function for register
        
        print( banner2 )
        
    elif choice == "2":
    
        print( 10*"_" , "User Login" , 10*"_")
        username = input("\nCyberLink Username > ")
        password = pwinput.pwinput("CyberLink Password > ", mask="*")
        print( 32 *"_")
        
        cyber_code = login(username, password)
        
        if cyber_code:
            while True:
                print("\nOptions [ .x.x.x.x.x.x.x. ] \n")
                print("( 1 ) Send message")
                print("( 2 ) Receive messages")
                print("( 3 ) Transfer file")
                print("( 4 ) List files")
                print("( 5 ) Download file")
                print("( 6 ) Server trace")
                print("( 7 ) Logout")
                
                action = input("\n[ Select an option ] > ")
                
                if action == "1":
                    receiver = input("Enter receiver's Cyber Code: ")
                    
                    while True :
                         message = input("\nEnter message: ")
                         message = " [ " + username + " ] : " + message  
                         send_data(cyber_code, receiver, message)
                elif action == "2":
                    receive_data(cyber_code)
                elif action == "3":
                    receiver = input("\nEnter receiver's Cyber Code: ")
                    filepath = input("Enter file path: ")
                    transfer_file(cyber_code, receiver, filepath)
                elif action == "4":
                    list_files(cyber_code)
                elif action == "5":
                    files = list_files(cyber_code)
                    if files:
                        file_id = input("\nEnter file ID to download: ")
                        save_dir = input("Enter save directory (or press Enter for current directory): ")
                        if not save_dir.strip():
                            save_dir = "."
                        download_file(cyber_code, file_id, save_dir)
                elif action == "6":
                    target = input("Enter target host to trace: ")
                    server_trace(cyber_code, target)
                elif action == "7":
                    print("Logging out...")
                    break
                else:
                    print("Invalid option, please try again.")
    elif choice == "3":
        print("Exiting program...")
    else:
        print("Invalid choice, please run the program again.")
