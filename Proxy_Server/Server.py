import socket
import threading
import re
import ssl
from Constants import ServerConsts
import DB_interaction
import WebSockComm as WebSocket
import requests


class Server():
    
    def __init__(self):
        self.URL_db = DB_interaction.init()
        # Set up the server socket to TCP
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Bind the server socket to a specific address and port
        self.server_socket.bind((ServerConsts.HOST,ServerConsts.PORT))
        #Start the proxy server
        self.start_proxy_server()
        

    # Function to start the proxy server
    def start_proxy_server(self):
        # Create a server socket to listen for incoming connections
        self.server_socket.listen()  # Listen for connections
        print(f"Proxy server is listening on port {ServerConsts.PORT}")

        # Loop to accept and handle incoming connections
        while True:
            client_socket, addr = self.server_socket.accept()
            print(f"Received connection from {addr}")

        # Create a new thread to handle the client connection
            client_handler = threading.Thread(target=Conn_Handler, args=(client_socket,self.URL_db))
            client_handler.start()
        #handle_client(client_socket)

class Conn_Handler():

    def __init__(self, client_socket, URL_db):
        self.URL_db = URL_db
        self.client_socket = client_socket
        self.handle_client()
        
    # Function to handle a single client connection
    def handle_client(self):
        # Perform handshake
        request = self.client_socket.recv(1024).decode('utf-8')
        print("----------------\n" + str(request) + "--------------")

        # Extract the host from the request headers
        host = re.search(r"Host: (.+)", request).group(1)

        if(self.URL_db.check_url_in_threat_list(str(host))):
            self.client_socket.send(self.unsafe_massege(host))
        else:
            self.client_socket.send(self.safe_massege(host))

    def unsafe_massege(self,host):
        print("sent unsafe message")
        return(f"HTTP/1.1 203 Host: {host} \r\n\r\n".encode())
    
    def safe_massege(self,host):
        print("sent safe message")
        return(f"HTTP/1.1 200 OK Host: {host} \r\n\r\n".encode())

# Start the proxy server
if (__name__ == '__main__'):
    Server()

