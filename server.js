const WebSocket = require('ws');
const http = require('http');

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.writeHead(200);
  res.end('Nexo relay ok');
});

const wss = new WebSocket.Server({ server });
const clients = new Map();
const queue = new Map();
const MAX_QUEUE = 200;
const TTL = 7 * 24 * 60 * 60 * 1000;

wss.on('connection', (ws) => {
  let myId = null;

  ws.on('message', (raw) => {
    let pkt;
    try { pkt = JSON.parse(raw); } catch { return; }

    if (pkt.type === 'REGISTER') {
      myId = pkt.id;
      clients.set(myId, ws);
      const q = (queue.get(myId) || []).filter(p => Date.now() - p._ts < TTL);
      q.forEach(p => { delete p._ts; ws.send(JSON.stringify(p)); });
      queue.delete(myId);
      ws.send(JSON.stringify({ type: 'REGISTERED', queued: q.length }));
      return;
    }

    if (pkt.type === 'PING') {
      ws.send(JSON.stringify({ type: 'PONG' }));
      return;
    }

    const to = pkt.to;
    if (!to) return;
    pkt.from = myId;
    const target = clients.get(to);

    if (target && target.readyState === WebSocket.OPEN) {
      target.send(JSON.stringify(pkt));
    } else if (pkt.type !== 'TYPING') {
      if (!queue.has(to)) queue.set(to, []);
      const q = queue.get(to);
      pkt._ts = Date.now();
      q.push(pkt);
      if (q.length > MAX_QUEUE) q.shift();
      if (myId && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'ACK', id: pkt.id, status: 'queued' }));
      }
    }
  });

  ws.on('close', () => { if (myId) clients.delete(myId); });
  ws.on('error', () => { if (myId) clients.delete(myId); });
});

setInterval(() => {
  const now = Date.now();
  for (const [id, q] of queue.entries()) {
    const fresh = q.filter(p => now - p._ts < TTL);
    if (!fresh.length) queue.delete(id);
    else queue.set(id, fresh);
  }
}, 3600000);

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => console.log(`Nexo relay on port ${PORT}`));
