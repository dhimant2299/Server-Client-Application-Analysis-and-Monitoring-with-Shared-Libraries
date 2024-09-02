import socket
import os
from tkinter import Tk
from tkinter.filedialog import askopenfilename

#constants
SERVER_HOST = 'localhost'
SERVER_PORT = 12345
BUFFER_SIZE = 1024

#function to send a login request
def send_login_request(sock):
    username = input("Enter Username: ").strip()
    password = input("Enter Password: ").strip()
    login_request = f"login,{username},{password}"
    sock.sendall(login_request.encode())
    response = sock.recv(BUFFER_SIZE).decode()
    print (f"server response: {response}")
    
#function to send a file upload request
def send_file_upload_request(sock):
    Tk().withdraw()
    filepath = askopenfilename()
    if not filepath:
        print("no file selected")
        return
    filesize = os.path.getsize(filepath)
    filename = os.path.basename(filepath)
    upload_request = f"upload,{filename},{filesize}"
    sock.sendall(upload_request.encode())
    
    response = sock.recv(BUFFER_SIZE).decode()
    if response == "upload,ready":
        with open(filepath, 'rb') as f:
            sock.sendall(f.read())
        print(sock.recv(BUFFER_SIZE).decode())
    else:
        print(f"file uplaod failed: {response}")

#Main function to run the client
def run_client (host,port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect((host,port))
            print(f"connected to server at {host}: {port}")
            while True:
                print("\n1.login\n2. Upload File\nType 'exit' to exit.")
                action_input = input("Select an action: " ).strip()
                
                if action_input =='1':
                    send_login_request(sock)
                elif action_input == '2':
                    send_file_upload_request(sock)
                elif action_input.lower() == 'exit':
                    print("exitting  the client")
                    break
                else:
                    print("Invalid selection. Please enter 1 2 or 'exit'")
        except ConnectionRefusedError:
            print(f"failed to connect to the server at {host}:{port}")
        except Exception as e:
            print(f"error {e}")
if __name__ == '__main__':
    run_client(SERVER_HOST,SERVER_PORT)

            
