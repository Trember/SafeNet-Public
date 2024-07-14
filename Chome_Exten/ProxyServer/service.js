// service.js
const Service = require('node-windows').Service;

// Create a new service object
const svc = new Service({
    name: 'SafeNet',
    description: 'My Node.js Application as a Windows Service that is a proxy',
    script: require('path').join(__dirname, 'ProxyServer.js'),
    // Define the service to start automatically
    start: 'auto'
});

// Listen for the "install" event, which indicates the process is available as a service
svc.on('install', () => {
    svc.start();
    console.log('Service installed');
});

svc.on('uninstall', () => {
    console.log('Service uninstalled');
});

//svc.uninstall();
svc.install();
