const express = require("express");
const WebSocket = require("ws");
const dgram = require("dgram");

const app = express();
app.use(express.static("public"));

const server = app.listen(3000, () =>
  console.log("Visualizer at http://localhost:3000")
);

const wss = new WebSocket.Server({ server });

// UDP listener (from Mininet nodes)
const udp = dgram.createSocket("udp4");
udp.bind(5005);

wss.on("connection", ws => {
  console.log("Visualizer client connected");
});

udp.on("message", msg => {
  const event = msg.toString();
  wss.clients.forEach(c => {
    if (c.readyState === WebSocket.OPEN) c.send(event);
  });
});
