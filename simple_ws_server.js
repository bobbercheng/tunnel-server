// Simple WebSocket server using Node.js built-in modules
const http = require('http');
const crypto = require('crypto');

// WebSocket GUID as per RFC 6455
const WS_MAGIC_STRING = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

function generateAcceptKey(key) {
  return crypto
    .createHash('sha1')
    .update(key + WS_MAGIC_STRING)
    .digest('base64');
}

function parseWebSocketFrame(buffer) {
  if (buffer.length < 2) return null;
  
  const firstByte = buffer[0];
  const secondByte = buffer[1];
  
  const fin = (firstByte & 0x80) === 0x80;
  const opcode = firstByte & 0x0f;
  const masked = (secondByte & 0x80) === 0x80;
  let payloadLength = secondByte & 0x7f;
  
  let offset = 2;
  
  if (payloadLength === 126) {
    payloadLength = buffer.readUInt16BE(offset);
    offset += 2;
  } else if (payloadLength === 127) {
    payloadLength = buffer.readBigUInt64BE(offset);
    offset += 8;
  }
  
  let maskKey = null;
  if (masked) {
    maskKey = buffer.slice(offset, offset + 4);
    offset += 4;
  }
  
  if (buffer.length < offset + payloadLength) return null;
  
  let payload = buffer.slice(offset, offset + Number(payloadLength));
  
  if (masked && maskKey) {
    for (let i = 0; i < payload.length; i++) {
      payload[i] ^= maskKey[i % 4];
    }
  }
  
  return { fin, opcode, payload };
}

function createWebSocketFrame(opcode, payload) {
  const payloadLength = payload.length;
  let frame;
  
  if (payloadLength < 126) {
    frame = Buffer.allocUnsafe(2 + payloadLength);
    frame[0] = 0x80 | opcode; // FIN = 1
    frame[1] = payloadLength;
    payload.copy(frame, 2);
  } else if (payloadLength < 65536) {
    frame = Buffer.allocUnsafe(4 + payloadLength);
    frame[0] = 0x80 | opcode;
    frame[1] = 126;
    frame.writeUInt16BE(payloadLength, 2);
    payload.copy(frame, 4);
  } else {
    frame = Buffer.allocUnsafe(10 + payloadLength);
    frame[0] = 0x80 | opcode;
    frame[1] = 127;
    frame.writeBigUInt64BE(BigInt(payloadLength), 2);
    payload.copy(frame, 10);
  }
  
  return frame;
}

const server = http.createServer();

server.on('upgrade', (request, socket, head) => {
  const key = request.headers['sec-websocket-key'];
  if (!key) {
    socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
    return;
  }
  
  const acceptKey = generateAcceptKey(key);
  const responseHeaders = [
    'HTTP/1.1 101 Switching Protocols',
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Accept: ${acceptKey}`,
    '', ''
  ].join('\r\n');
  
  socket.write(responseHeaders);
  
  console.log(`🔗 WebSocket connection established from ${socket.remoteAddress}`);
  
  // Send welcome message
  const welcome = JSON.stringify({
    type: 'welcome',
    message: 'Connected to Node.js WebSocket server!',
    timestamp: new Date().toISOString()
  });
  const welcomeFrame = createWebSocketFrame(1, Buffer.from(welcome));
  socket.write(welcomeFrame);
  
  socket.on('data', (data) => {
    const frame = parseWebSocketFrame(data);
    if (!frame) return;
    
    if (frame.opcode === 1) { // Text frame
      const message = frame.payload.toString('utf8');
      console.log(`📨 Received: ${message}`);
      
      // Echo the message back
      const echo = JSON.stringify({
        type: 'echo',
        original: message,
        echo: `Server echoes: ${message}`,
        timestamp: new Date().toISOString()
      });
      const echoFrame = createWebSocketFrame(1, Buffer.from(echo));
      socket.write(echoFrame);
      console.log(`📤 Sent echo: ${echo}`);
    } else if (frame.opcode === 8) { // Close frame
      console.log(`🔚 Connection closing`);
      socket.end();
    }
  });
  
  socket.on('error', (err) => {
    console.error(`❌ Socket error: ${err.message}`);
  });
  
  socket.on('close', () => {
    console.log(`🔚 Connection closed`);
  });
});

const PORT = 5001;
server.listen(PORT, '127.0.0.1', () => {
  console.log(`🚀 WebSocket server listening on ws://127.0.0.1:${PORT}`);
  console.log(`📡 Ready to test WebSocket tunneling!`);
  console.log(`🔗 Connect via tunnel: ws://localhost:9998/testws/`);
});