// background.js

let socket;

async function connectWebSocket() {
  socket = new WebSocket('ws:localhost:8089');

  socket.onopen = function(event) {
    console.log('WebSocket connected');
    // Additional handling when WebSocket opens
  };

  socket.onmessage = function(event) {
    console.log('Message from server ', event.data);
    // Handle incoming messages from WebSocket server
  };

  socket.onclose = function(event) {
    console.log('WebSocket closed');
    // Handle WebSocket close
  };

  socket.onerror = function(error) {
    console.error('WebSocket Error: ', error);
    // Handle WebSocket errors
  };
}

// Example function to send a message through WebSocket
function sendMessage(message) {
  if (socket.readyState === WebSocket.OPEN) {
    socket.send(message);
  } else {
    console.error('WebSocket not connected');
  }
}

// Call connectWebSocket when extension is first installed or loaded
connectWebSocket();

// Optional: Listen for messages from content scripts or other parts of the extension
chrome.runtime.onMessage.addListener(function(message, sender, sendResponse) {
  if (message.type === 'send_message') {
    sendMessage(message.content);
  }
  else if (message.action === 'blackPageDetected') {
    // Open extension popup when black page is detected
    chrome.action.openPopup();
}
});

// Required for Manifest V3: Handle lifecycle events
chrome.runtime.onInstalled.addListener(() => {
  // Connect WebSocket on install or upgrade
  connectWebSocket();
});
