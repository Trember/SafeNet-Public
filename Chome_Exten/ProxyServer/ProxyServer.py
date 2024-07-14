import socket
import ssl
import os
import threading

PORT = 8080
forbidden_sites = {}

def handle_client(client_socket):
    print("Client connected to Proxy")
    
    data = client_socket.recv(4096)
    print(data.decode())
    is_connection_tls = b"CONNECT" in data
    print(str(is_connection_tls))
    
    server_port = 80
    server_addr = None

    if is_connection_tls:
        server_port = 80
        server_addr = data.split(b"CONNECT")[1].split(b" ")[1].split(b":")[0].decode()
        print(server_addr)
    else:
        server_addr = data.split(b"Host: ")[1].split(b"\\n")[0].decode()

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    with socket.create_connection(('127.0.0.1', 8069)) as proxy_to_safe_net_socket:
        with context.wrap_socket(proxy_to_safe_net_socket, server_hostname='127.0.0.1') as ssock:
            #connect_request = f'CONNECT {server_addr}:{server_port} HTTP/1.1\r\nHost: {server_addr}:{server_port}\r\n\r\n'.encode()
            connect_request = data
            print("-------------")
            print(connect_request.decode())
            ssock.sendall(connect_request)
            print("Proxy connected to SafeNet")
        
            if is_connection_tls:
                client_socket.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
                print("Wrote back")
            else:
                if server_addr in forbidden_sites and forbidden_sites[server_addr] == 1:
                    data = replace_port(data.decode(), -1).encode()
                    print(data.decode())
                ssock.sendall(data)
            
            while True:
                try:
                    proxy_data = b''
                    while True:
                        data = ssock.recv(4096)
                        if len(data) == 0:
                            break
                        proxy_data += data
                    if not proxy_data:
                        break
                    if b" 203 " in proxy_data:
                        forbidden_sites[server_addr] = 0  # 0 is not approved, 1 is approved
                    print('Received: ' + proxy_data.decode())
                    client_socket.sendall(proxy_data)
                except Exception as e:
                    print("Proxy to server error")
                    print(e)
                    break

def replace_port(url_string, new_port):
    import re
    return re.sub(r":\d+", f":{new_port}", url_string)

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', PORT))
    server.listen()
    print(f"Server running on PORT: {PORT}")

    try:
        while True:
            client_socket, addr = server.accept()
            threading.Thread(target=handle_client, args=(client_socket,)).start()
    except KeyboardInterrupt:
        print("Server shutting down")
    finally:
        server.close()

if __name__ == "__main__":
    main()
