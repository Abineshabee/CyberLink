# CyberLink - Secure Communication Platform

CyberLink is a secure communication platform that allows users to exchange messages and files with end-to-end encryption. The application consists of a Flask-based server and a Python client that work together to provide secure communications.

## Features

- User registration and login with encrypted credentials
- End-to-end encrypted messaging
- Secure file transfer capabilities
- Network tracing tools
- Unique "Cyber Code" identifiers for each user

## Setup Instructions

### Prerequisites

- Python 3.8 or higher
- Required Python packages (install using `pip install -r requirements.txt`)

### Installation

1. Clone or download the repository
2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

### Running the Server

1. Start the Flask server:
   ```
   python server.py
   ```
   The server will run on `0.0.0.0:5000` by default (accessible on all network interfaces).

### Running the Client

1. Make sure the server is running
2. Start the client application:
   ```
   python client.py
   ```

## Usage

### Registration
1. Select Option 1 from the main menu
2. Enter a username and password
3. Your unique Cyber Code will be generated - save this for future logins

### Login
1. Select Option 2 from the main menu
2. Enter your username and password
3. Upon successful login, you'll see your Cyber Code

### Sending Messages
1. After login, select Option 1
2. Enter the recipient's Cyber Code
3. Type your message

### Receiving Messages
1. After login, select Option 2
2. The client will continuously check for new messages
3. Press Ctrl+C to stop receiving messages

### File Transfer
1. Select Option 3 to send a file
2. Enter the recipient's Cyber Code
3. Provide the full path to the file you want to send

### Downloading Files
1. Select Option 4 to list available files
2. Select Option 5 to download a file
3. Enter the file ID from the list
4. Specify a download directory (or press Enter for current directory)

### Network Tracing
1. Select Option 6 to perform network tracing
2. Enter a target hostname or IP address
3. View DNS information and trace results
4. Results are saved to a text file for future reference

## Security Features

- RSA encryption for user authentication
- Fernet symmetric encryption for message content
- Secure file transfer with validation
- Unique Cyber Codes for user identification

## Limitations and Warnings

- Debug mode is enabled on the server (not recommended for production)
- The application uses a local SQLite database
- File type restrictions are enforced for security

## License

This project is intended for educational purposes only.
