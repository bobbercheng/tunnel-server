#!/usr/bin/env node

const http = require('http');
const crypto = require('crypto');

const url = 'localhost:9999';
const path = '/testws';
const key = crypto.randomBytes(16).toString('base64');

console.log(`🔗 Connecting to WebSocket tunnel: ws://${url}${path}`);

const options = {
  hostname: 'localhost',
  port: 9999,
  path: path,
  method: 'GET',
  headers: {
    'Connection': 'Upgrade',
    'Upgrade': 'websocket',
    'Sec-WebSocket-Version': '13',
    'Sec-WebSocket-Key': key
  }
};

const req = http.request(options);

req.on('upgrade', (res, socket, head) => {
  console.log('✅ WebSocket upgrade successful!');
  console.log('📨 Server response:', res.statusCode, res.statusMessage);
  
  // Create a simple text frame
  function createFrame(message) {
    const payload = Buffer.from(message, 'utf8');
    const frame = Buffer.allocUnsafe(6 + payload.length);
    
    frame[0] = 0x81; // FIN=1, opcode=1 (text)
    frame[1] = 0x80 | payload.length; // MASK=1, payload length
    
    // Mask key
    const mask = crypto.randomBytes(4);
    mask.copy(frame, 2);
    
    // Masked payload
    for (let i = 0; i < payload.length; i++) {
      frame[6 + i] = payload[i] ^ mask[i % 4];
    }
    
    return frame;
  }
  
  // Send test message
  setTimeout(() => {
    console.log('📤 Sending test message...');
    const frame = createFrame('Hello from Node.js WebSocket client!');
    socket.write(frame);
  }, 500);
  
  // Send JSON message
  setTimeout(() => {
    console.log('📤 Sending JSON message...');
    const jsonMsg = JSON.stringify({
      type: 'test',
      message: 'JSON test from Node.js client',
      timestamp: new Date().toISOString()
    });
    const frame = createFrame(jsonMsg);
    socket.write(frame);
  }, 1500);
  
  // Listen for incoming frames
  socket.on('data', (data) => {
    if (data.length >= 2) {
      const opcode = data[0] & 0x0f;
      if (opcode === 1) { // Text frame
        let payloadLength = data[1] & 0x7f;
        let offset = 2;
        
        if (payloadLength === 126) {
          payloadLength = data.readUInt16BE(offset);
          offset += 2;
        } else if (payloadLength === 127) {
          payloadLength = data.readBigUInt64BE(offset);
          offset += 8;
        }
        
        const payload = data.slice(offset, offset + Number(payloadLength));
        console.log('📨 Received:', payload.toString('utf8'));
      }
    }
  });
  
  socket.on('end', () => {
    console.log('🔚 Connection ended');
  });
  
  socket.on('error', (err) => {
    console.error('❌ Socket error:', err.message);
  });
  
  // Close after 3 seconds
  setTimeout(() => {
    console.log('🔚 Closing connection...');
    socket.end();
  }, 3000);
});

req.on('error', (err) => {
  console.error('❌ Request error:', err.message);
});

req.end();