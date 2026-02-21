import React, { useState, useEffect, useRef } from "react";

const STYLES = {
  container: { maxWidth: 600, margin: "0 auto", padding: 20, fontFamily: "system-ui, sans-serif" },
  header: { borderBottom: "2px solid #333", paddingBottom: 10, marginBottom: 20 },
  status: (connected) => ({
    display: "inline-block", width: 10, height: 10, borderRadius: "50%",
    background: connected ? "#4caf50" : "#f44336", marginRight: 8,
  }),
  messages: {
    height: 400, overflowY: "auto", border: "1px solid #ddd", borderRadius: 8,
    padding: 12, marginBottom: 12, background: "#fafafa",
  },
  msg: { margin: "8px 0", padding: "8px 12px", borderRadius: 6, background: "#fff", boxShadow: "0 1px 2px rgba(0,0,0,.1)" },
  user: { fontWeight: 700, color: "#1976d2", marginRight: 8 },
  time: { fontSize: 11, color: "#999" },
  form: { display: "flex", gap: 8 },
  input: { flex: 1, padding: "8px 12px", borderRadius: 6, border: "1px solid #ddd", fontSize: 14 },
  btn: { padding: "8px 20px", borderRadius: 6, border: "none", background: "#1976d2", color: "#fff", cursor: "pointer", fontSize: 14 },
};

export default function App() {
  const [messages, setMessages] = useState([]);
  const [text, setText] = useState("");
  const [user, setUser] = useState("");
  const [connected, setConnected] = useState(false);
  const wsRef = useRef(null);
  const bottomRef = useRef(null);

  useEffect(() => {
    // Determine WebSocket URL based on current page location
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${proto}//${window.location.host}/ws`;

    function connect() {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        setTimeout(connect, 2000);
      };
      ws.onmessage = (e) => {
        const msg = JSON.parse(e.data);
        if (msg.type === "history") {
          setMessages(msg.data);
        } else if (msg.type === "message") {
          setMessages((prev) => [...prev, msg.data]);
        }
      };
    }
    connect();
    return () => wsRef.current?.close();
  }, []);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const send = (e) => {
    e.preventDefault();
    if (!text.trim()) return;
    const name = user.trim() || "anon";
    wsRef.current?.send(JSON.stringify({ type: "message", user: name, text }));
    setText("");
  };

  return (
    <div style={STYLES.container}>
      <div style={STYLES.header}>
        <h2>Chat App <span style={STYLES.status(connected)} title={connected ? "Connected" : "Disconnected"} /></h2>
      </div>

      <div style={{ marginBottom: 12 }}>
        <input
          style={{ ...STYLES.input, width: 200 }}
          placeholder="Your name"
          value={user}
          onChange={(e) => setUser(e.target.value)}
        />
      </div>

      <div style={STYLES.messages}>
        {messages.map((m) => (
          <div key={m.id} style={STYLES.msg}>
            <span style={STYLES.user}>{m.user}</span>
            <span style={STYLES.time}>{new Date(m.ts).toLocaleTimeString()}</span>
            <div>{m.text}</div>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>

      <form onSubmit={send} style={STYLES.form}>
        <input
          style={STYLES.input}
          placeholder="Type a message..."
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
        <button style={STYLES.btn} type="submit">Send</button>
      </form>
    </div>
  );
}
