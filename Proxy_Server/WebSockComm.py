import base64
import hashlib


def create_handshake_response(key):
    GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
    accept_key = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
    return (
        'HTTP/1.1 101 Switching Protocols\r\n'
        'Upgrade: websocket\r\n'
        'Connection: Upgrade\r\n'
        'Sec-WebSocket-Accept: {}\r\n\r\n'.format(accept_key)
    )

def receive_data(client_socket):
    data = client_socket.recv(1024)
    if not data:
        return None
    # Decode the WebSocket frame (simplified)
    payload_len = data[1] & 127
    if payload_len == 126:
        mask = data[4:8]
        payload = data[8:]
    elif payload_len == 127:
        mask = data[10:14]
        payload = data[14:]
    else:
        mask = data[2:6]
        payload = data[6:]

    decoded = bytearray([payload[i] ^ mask[i % 4] for i in range(len(payload))])
    return decoded.decode()

def send_data(client_socket, message):
    # Encode the message using WebSocket frame format (simplified)
    payload = message.encode()
    frame = [129]
    frame += [len(payload)]
    frame_to_send = bytearray(frame) + payload
    client_socket.send(frame_to_send)

def parse_headers(request):
    headers = {}
    lines = request.split('\r\n')
    for line in lines[1:]:
        if ': ' in line:
            key, value = line.split(': ', 1)
            headers[key] = value
    return headers

