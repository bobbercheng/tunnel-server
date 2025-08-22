#!/usr/bin/env node

const WebSocket = require('ws');

const url = 'ws://localhost:9999/testws';
console.log(`🔗 Connecting to WebSocket tunnel: ${url}`);

const ws = new WebSocket(url);

ws.on('open', function open() {
  console.log('✅ WebSocket connection opened!');
  
  // Send test messages
  console.log('📤 Sending test message...');
  ws.send('Hello from WebSocket client!');
  
  setTimeout(() => {
    console.log('📤 Sending JSON test...');
    ws.send(JSON.stringify({
      type: 'test',
      message: 'JSON test message',
      timestamp: new Date().toISOString()
    }));
  }, 1000);
  
  setTimeout(() => {
    console.log('📤 Sending final message...');
    ws.send('Final test message');
  }, 2000);
  
  // Close after 3 seconds
  setTimeout(() => {
    console.log('🔚 Closing connection...');
    ws.close();
  }, 3000);
});

ws.on('message', function message(data) {
  console.log('📨 Received:', data.toString());
});

ws.on('close', function close(code, reason) {
  console.log(`🔚 Connection closed (code: ${code}, reason: ${reason})`);
});

ws.on('error', function error(err) {
  console.error('❌ WebSocket error:', err.message);
});