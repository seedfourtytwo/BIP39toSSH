const { spawn } = require('child_process');
const path = require('path');

// Start the server
const server = spawn('node', ['src/server.js'], {
    stdio: 'inherit',
    shell: true
});

// Handle server process
server.on('error', (err) => {
    console.error('Failed to start server:', err);
    process.exit(1);
});

// Handle process termination
process.on('SIGINT', () => {
    server.kill('SIGINT');
    process.exit();
}); 