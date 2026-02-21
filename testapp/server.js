const express = require("express");
const http = require("http");
const { WebSocketServer } = require("ws");
const cors = require("cors");
const path = require("path");

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: "/ws" });

app.use(cors());
app.use(express.json());

// Serve built frontend if exists
app.use(express.static(path.join(__dirname, "frontend/dist")));

// In-memory messages
const messages = [];

// REST: get messages
app.get("/api/messages", (req, res) => {
  res.json(messages);
});

// REST: post message
app.post("/api/messages", (req, res) => {
  const msg = {
    id: Date.now(),
    user: req.body.user || "anon",
    text: req.body.text || "",
    ts: new Date().toISOString(),
  };
  messages.push(msg);
  // Broadcast to all WebSocket clients and SSE handlers
  const data = JSON.stringify({ type: "message", data: msg });
  wss.clients.forEach((c) => {
    if (c.readyState === 1) c.send(data);
  });
  (wss._sseHandlers || []).forEach((h) => h(data));
  res.status(201).json(msg);
});

// SSE: stream messages as they arrive
app.get("/api/stream", (req, res) => {
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
  });
  res.write("data: connected\n\n");

  const onMessage = (msg) => {
    res.write(`data: ${JSON.stringify(msg)}\n\n`);
  };
  const interval = setInterval(() => {
    res.write(": keepalive\n\n");
  }, 15000);

  // Listen for new messages via a simple event pattern
  const handler = (data) => {
    try {
      const parsed = JSON.parse(data);
      if (parsed.type === "message") onMessage(parsed.data);
    } catch {}
  };
  wss._sseHandlers = wss._sseHandlers || [];
  wss._sseHandlers.push(handler);

  req.on("close", () => {
    clearInterval(interval);
    wss._sseHandlers = wss._sseHandlers.filter((h) => h !== handler);
  });
});

// Health check
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", messages: messages.length, clients: wss.clients.size });
});

// WebSocket: real-time chat
wss.on("connection", (ws) => {
  console.log("WebSocket client connected");
  ws.send(JSON.stringify({ type: "history", data: messages.slice(-50) }));

  ws.on("message", (raw) => {
    try {
      const msg = JSON.parse(raw);
      if (msg.type === "message") {
        const entry = {
          id: Date.now(),
          user: msg.user || "anon",
          text: msg.text || "",
          ts: new Date().toISOString(),
        };
        messages.push(entry);
        const data = JSON.stringify({ type: "message", data: entry });
        wss.clients.forEach((c) => {
          if (c.readyState === 1) c.send(data);
        });
        // Notify SSE handlers
        (wss._sseHandlers || []).forEach((h) => h(data));
      }
    } catch {}
  });

  ws.on("close", () => console.log("WebSocket client disconnected"));
});

// SPA fallback
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "frontend/dist/index.html"));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Chat app running on http://localhost:${PORT}`));
