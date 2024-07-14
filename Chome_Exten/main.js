import WebSocket, { Server } from 'ws';

const server = new Server({ port: 8080 });

server.on('connection', (socket) => {
    console.log('Client connected');

  // When a message is received from the client, forward it to the target server
socket.on('message', (message) => {
    console.log('Received message from client:', message);

    // Forward the message to the target WebSocket server
    const targetSocket = new WebSocket('wss://target-websocket-server.com');
    
    targetSocket.on('open', () => {
      targetSocket.send(message);
    });

    // Send back the response from the target server to the client
    targetSocket.on('message', (response) => {
      console.log('Received response from target server:', response);
      socket.send(response);
    });

    targetSocket.on('close', () => {
      console.log('Target server connection closed');
    });

    targetSocket.on('error', (error) => {
      console.log('Target server error:', error);
      socket.send(JSON.stringify({ error: 'Target server error' }));
    });
  });

  socket.on('close', () => {
    console.log('Client disconnected');
  });

  socket.on('error', (error) => {
    console.log('Client error:', error);
  });
});

console.log('WebSocket proxy server running on ws://localhost:8080');
