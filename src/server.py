import socket
import csv
import os
import hashlib

# Define constants

from threading import Thread

#Constants
SERVER_PORT = 12345
BUFFER_SIZE = 1024
MAX_FILE_SIZE = 20 *1024
ALLOWED_EXTENSION = '.csv'

#function to verify credentials
def verify_credentials (username, password):
    try:
        with open('users/plaintext_users_and_passwords.csv', mode='r') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                if row['username'] == username and row['password'] == password:
                    return True
    except FileNotFoundError:
        print ("Error: plaintext_users_and_passwords.csv file not found")
    except Exception as e:
        print(f"Error verifying credentials: {e}")
    return False

# function to handle client requests
def handle_client_connection(client_socket, addr):
    try:
        while True:
            request = client_socket.recv(BUFFER_SIZE).decode()
            if not request:
                print(f"Connection with {addr} closed by the client")
                break
            print(f"request from {addr}: {request}")
            
            if request.startswith('login'):
                _, username, password = request.split(',')
                if verify_credentials(username,password):
                    client_socket.sendall("login,success".encode())
                    print(f"Login successful for {username}")
                else:
                    client_socket.sendall("login,fail".encode())
                    print(f"Login failed for {username}")
                    
            elif request.startswith('upload'):
                _,filename,filesize = request.split(',')
                filesize = int(filesize)
                
                if not filename.endswith(ALLOWED_EXTENSION) or filesize > MAX_FILE_SIZE:
                    client_socket.sendall("upload,fail".encode())
                    print(f"File upload failed for {filename}: invalid file or size")  
                    continue
                client_socket.sendall("upload,ready".encode())
                file_content = client_socket.recv(filesize)
                
                print(f"received file: {filename}")
                client_socket.sendall("upload,success".encode())
            
            else:
                client_socket.sendall("error,unknown command".encode())
                print(f"Unknown command form {addr}:{request}")
                
    except Exception as e:
        print(f"Error handling connection with {addr}:{e}")
    
    finally:
        client_socket.close()


#Main server function
def start_server(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('',port))
    server_socket.listen(5)
    print(f"Server listening on port {port}")
    
    try:
        while True:
            client_socket, addr = server_socket.accept()
            print(f"Client connected from {addr}")
            client_thread = Thread(target=handle_client_connection, args=(client_socket,addr))
            client_thread.start()
            
    except KeyboardInterrupt:
        print("\nServer shutting down...")
    finally:
        server_socket.close()

if __name__ == '__main__':
    start_server(SERVER_PORT)
