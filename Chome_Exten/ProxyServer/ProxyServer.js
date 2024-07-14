const net = require('net');
const { hostname } = require('os');
const WebSocket = require('ws');
const app = net.createServer();


const PORT = process.env.PORT || 8080;
var forbiddenSites = {};



const UnSafeSite = "127.0.0.1:8089";

app.on("connection", (clientToProxySocket) => {
  console.log("Client connected to Proxy");

  clientToProxySocket.once("data", async (data) => {
    console.log(data.toString());
    let isConnectionTLS = data.toString().indexOf("CONNECT") !== -1;
    console.log(isConnectionTLS.toString());

    let serverPort = 80;
    let serverAddr;

    if (isConnectionTLS) {
      serverPort = 443;
      serverAddr = data.toString().split("CONNECT")[1].split(" ")[1].split(":")[0];
      console.log(serverAddr);
    } else {
      serverAddr = data.toString().split("Host: ")[1].split("\n")[0].trim();
    }

    const options = {
      host: '127.0.0.1',
      port: 8069,
      //ca: [fs.readFileSync('path/to/ca-cert.pem')],
      secureProtocol: 'TLSv1_2_method', // Use TLS 1.2
      ciphers: 'ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA'
    };

    try {
      if(!(serverAddr in forbiddenSites)){
        const isAllowed = await checkSafeNet(options, serverAddr);
        if (!isAllowed) {
          serveBlackPage(clientToProxySocket);
          console.log("redirecting");
          return;
      }}
      else if(forbiddenSites[serverAddr] == 0) {
          serveBlackPage(clientToProxySocket);
          console.log("redirecting");
          return;
      }

      let proxyToServerSocket = net.createConnection({
        host: serverAddr,
        port: serverPort,
      }, () => {
        console.log("Proxy connected to server");
      });

      if (isConnectionTLS) {
        clientToProxySocket.write("HTTP/1.1 200 OK\r\n\r\n");
        console.log("Wrote back");
      }

      clientToProxySocket.pipe(proxyToServerSocket);
      proxyToServerSocket.pipe(clientToProxySocket);

      proxyToServerSocket.on("error", (err) => {
        console.log("Proxy to server error");
        console.log(err);
      });

      clientToProxySocket.on("error", (err) => {
        console.log("Client to proxy error");
      });

      proxyToServerSocket.on("close", () => {
        console.log("Server connection closed");
      });

      clientToProxySocket.on("close", () => {
        console.log("Client connection closed");
      });

    } catch (error) {
      console.error('Error connecting to SafeNet:', error);
      clientToProxySocket.end('HTTP/1.1 500 Internal Server Error\r\n\r\n');
    }
  });
});

function serveBlackPage(clientSocket) {
  const htmlContent = `
    HTTP/1.1 200 OK\r\n
    Content-Type: text/html\r\n
    \r\n
    <html>
    <head>
      <meta charset="UTF-8">
      <meta name="identifier" content="Safe-Net-Black-Page">
      <title>Access Forbidden</title>
      <style>
        body {
          background-color: black;
          color: white;
          text-align: center;
          padding-top: 50px;
        }
      </style>
    </head>
    <body>
      <h1>Access Forbidden</h1>
      <p>You are being redirected...</p>
    </body>
    </html>
  `;
clientSocket.end(htmlContent);
}
function checkSafeNet(options, serverAddr) {
  return new Promise((resolve, reject) => {
    const proxyToSafeNetSocket = net.connect(options, () => {
      const connectRequest = `CONNECT Host: ${serverAddr}\r\n\r\n`;
      console.log("-------------");
      console.log(connectRequest);
      const connectRequestBuffer = Buffer.from(connectRequest, 'utf-8');
      proxyToSafeNetSocket.write(connectRequestBuffer);
      console.log("Proxy connected to SafeNet");
    });

    proxyToSafeNetSocket.on('data', (data) => {
      const dataStr = data.toString();
      if (dataStr.includes("HTTP/1.1 203")) {
        forbiddenSites[serverAddr] = 0; // Add site to forbiddenSites with value 0
        console.log("Site forbidden");
        console.log(forbiddenSites);
        resolve(false); // Not allowed
      } else {
        resolve(true); // Allowed
      }
      proxyToSafeNetSocket.end();
    });

    proxyToSafeNetSocket.on("error", (err) => {
      console.log("Proxy to SafeNet error");
      console.log(err);
      reject(err);
    });
  });
}

app.listen({ host: '127.0.0.1', port: PORT }, () => {
  console.log("Server running on PORT:", PORT);
});


// Create a new WebSocket server
const wss = new WebSocket.Server({ port: 8089 });

// Event listener for new connections
wss.on('connection', function connection(ws) {
  console.log('extention connected!');

  // Event listener for messages from clients
  ws.on('message', function incoming(message) {
    console.log('Received message:', message);
    let hostname = message.toString().split("Host: ")[1].split("\n")[0].trim()
    if (Object.keys(forbiddenSites).includes(hostname)) {
      forbiddenSites[hostname] = 1;
      console.log(forbiddenSites);
    }
    console.log("tring to unlock V");
    console.log(hostname);

  });

  // Event listener for when a client disconnects
  ws.on('close', function close() {
    console.log('A client disconnected');
  });
});

console.log('WebSocket server is listening on ws://localhost:8081');
