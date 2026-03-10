/**
 * Nexo — Relay Server com FCM Push Notifications
 * Mensagens criptografadas passam por aqui mas NAO sao armazenadas.
 */
const WebSocket = require('ws');
const http = require('http');
const https = require('https');

// ── FCM V1 API ─────────────────────────────────────────
const FCM_PROJECT_ID = 'nexo-ef442';

// Service account credentials (from google-services JSON)
const SERVICE_ACCOUNT = {
  client_email: 'firebase-adminsdk-fbsvc@nexo-ef442.iam.gserviceaccount.com',
  private_key: `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDmCxJtln5qy6E3
HmjC1C3ZFKcLPyMeEhY0rkN5gS5Ju7vLp2EvQ63ybdd1cMBYithyfiK9yZqHwu23
+Z/JLigb/Z81obaCSetVOLWgZiAIpoLTGfWfJSFJWyh9PcQGYBKt+yaiZ4/smWfm
dQixnPqj2IC/ffzWDXBLC4y8GjjtlJD1xBCn6sNeCj6/sTNUOAdAf5rC0HtH0tkx
c762X3i/iy0qJEs6OQ0sHFFGjWpmrW/NbcII3dCR+pdIGW8RDY965gIRo/cCqqLs
9zhxpi0YmyHp/ws4PDQ+6K058jvFmgHNnZMaQXbzL+QD81T+8dqeZ/9bHTQcueNl
MjNDwuZ7AgMBAAECggEAEc2pj3GmNv2rbGieEvX41mQSyXwJa7panZke/7hPrMUq
s4gwrUe/npOBqUUgnbmhJrs8VRPVMcyUOTjIdPltgT0PpUbuqQavf9jztYYx1HmO
hmfr6nUlLlgvugGduiCVUYGua8M4EEePEvbbxWMwwp1u2WMWvjosBqLOMYCWB0zi
miW+X/qZzs7d7IYxNwqvdp9USkjAJepa4gf7z1IgRcouIQCdolZI2xKICfWfQcjQ
BH3sUTKskou7smLaZXrMuLOfMB5lKNhmc6FU2PO1vb2H7XVhGrpV5CUvfgk812PK
730b7mgxvZM1BffFxxop+VG+keJWLWEufK2fM9M4gQKBgQD2MjDRl0S37fbOJCBc
MabZvROp35Z0COirvIeQWv7iuu3u/ZW9vhMmENsyXQLGu4CGj8Lf+XvQ4xgQPqQC
2XKEft2UBSUeZeK32oRf2fAvOy9miGA/UshtUV1uivu7IdWDmm7hYixi6SaPbvC+
fyylkCzczPvRsh4yr+uwsuEsvQKBgQDvNDbAy41S1jMZn2VYfGoWBx3dBUtEsECM
H/uiR0rNV0Q2V2vlXHR60s5J5AGx1MMHQc8u0t2rbqrkz2MCz/lq6KJHGLslxhcY
fxPur4GQxQdOnLV7IkAPr5wFLu0R+IfOypmGVihz2VUcZYZvyuCcP7V80eutiOyn
7s8yixs/lwKBgEjF1UBe4mUr5gRREW+vDY7XIPTZrnNmHsCE3d2ByE3ky2gVdSm9
AZQhC74gXjjaIPhmIbSYfbMX2GqrSmVBuTjdz+LNEQhCWNUn7QZ3DogeUCxLXxPty
0OPfZSrD0l0iRya7g4MDrfMez9MeC/ODTAM0ds5dmSIG8H4zGgwFFCJRAoGALX0h
eHJ9MqaXWyUL0dL/HadGz5RFJw/ZhoxCfy7Nk9UnnKntU9XMNNtH7ZdVlyrd19B1
BPOGwiYui4rAynUgems5CQoz9NAB7l+kO7zWh+BgLlvwyzTNN+5uXjH5VXSM5w9y
OLDDypwm6lqIQVQ0eKJI8i69gefLEXiBoJwBl4sCgYAx+1iH5cgvC6c5Zm4SiPDL
oNDz6GlC2N9s0m4AWCp1jWkpuVvhm+mMqqiZgshRKuXMbtTJmvQD9704GoMJ3Bb3
sa9FCbKbFjuIOM9vBm3lm+y8ylooFLMjD+7Nk1ArC6skMsE8MgkYJW6DUUDBuTQb
2lYie4TUOt+ZPXmyOl4amw==
-----END PRIVATE KEY-----`
};

// peerId -> FCM token
const fcmTokens = new Map();

// Generate OAuth2 access token for FCM V1
let _fcmToken = null;
let _fcmTokenExpiry = 0;

async function getFCMAccessToken() {
  if (_fcmToken && Date.now() < _fcmTokenExpiry) return _fcmToken;

  // Create JWT
  const crypto = require('crypto');
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    iss: SERVICE_ACCOUNT.client_email,
    scope: 'https://www.googleapis.com/auth/firebase.messaging',
    aud: 'https://oauth2.googleapis.com/token',
    exp: now + 3600,
    iat: now
  })).toString('base64url');

  const sign = crypto.createSign('RSA-SHA256');
  sign.update(`${header}.${payload}`);
  const signature = sign.sign(SERVICE_ACCOUNT.private_key, 'base64url');
  const jwt = `${header}.${payload}.${signature}`;

  // Exchange JWT for access token
  return new Promise((resolve, reject) => {
    const body = `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`;
    const req = https.request({
      hostname: 'oauth2.googleapis.com',
      path: '/token',
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': body.length }
    }, res => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          _fcmToken = json.access_token;
          _fcmTokenExpiry = Date.now() + (json.expires_in - 60) * 1000;
          resolve(_fcmToken);
        } catch(e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

async function sendFCMNotification(fcmToken, title, body, data = {}) {
  try {
    const accessToken = await getFCMAccessToken();
    const message = {
      message: {
        token: fcmToken,
        notification: { title, body },
        android: {
          priority: 'high',
          notification: {
            sound: 'default',
            channel_id: 'nexo_calls',
            priority: 'max',
            visibility: 'public'
          }
        },
        data: Object.fromEntries(Object.entries(data).map(([k,v]) => [k, String(v)]))
      }
    };
    const payload = JSON.stringify(message);
    return new Promise((resolve) => {
      const req = https.request({
        hostname: 'fcm.googleapis.com',
        path: `/v1/projects/${FCM_PROJECT_ID}/messages:send`,
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload)
        }
      }, res => {
        let d = '';
        res.on('data', c => d += c);
        res.on('end', () => {
          console.log('[FCM] sent:', res.statusCode, d.slice(0, 100));
          resolve(res.statusCode === 200);
        });
      });
      req.on('error', e => { console.error('[FCM] error:', e.message); resolve(false); });
      req.write(payload);
      req.end();
    });
  } catch(e) {
    console.error('[FCM] failed:', e.message);
    return false;
  }
}

// ── HTTP Server ────────────────────────────────────────
const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (req.url === '/health') {
    res.writeHead(200);
    res.end(JSON.stringify({ ok: true, clients: clients.size, ts: Date.now() }));
  } else {
    res.writeHead(200);
    res.end('Nexo relay ok');
  }
});

const wss = new WebSocket.Server({ server, maxPayload: 20 * 1024 * 1024 });

const clients = new Map();
const queue = new Map();
const MAX_QUEUE = 200;
const QUEUE_TTL = 7 * 24 * 60 * 60 * 1000;

wss.on('connection', (ws) => {
  let myId = null;

  ws.on('message', (raw) => {
    let pkt;
    try { pkt = JSON.parse(raw); } catch { return; }

    switch (pkt.type) {

      case 'REGISTER': {
        myId = pkt.id;
        clients.set(myId, ws);
        // Register FCM token if provided
        if (pkt.fcmToken) {
          fcmTokens.set(myId, pkt.fcmToken);
          console.log('[FCM] token registered for', myId.slice(0, 8));
        }
        // Flush queued packets
        const q = queue.get(myId) || [];
        const now = Date.now();
        const fresh = q.filter(p => (now - p._ts) < (p._ttl || QUEUE_TTL));
        fresh.forEach(p => { delete p._ts; delete p._ttl; ws.send(JSON.stringify(p)); });
        queue.delete(myId);
        ws.send(JSON.stringify({ type: 'REGISTERED', queued: fresh.length }));
        break;
      }

      case 'FCM_TOKEN': {
        // Update FCM token
        if (myId && pkt.token) {
          fcmTokens.set(myId, pkt.token);
          console.log('[FCM] token updated for', myId.slice(0, 8));
        }
        break;
      }

      case 'MSG':
      case 'AUDIO':
      case 'IMAGE':
      case 'TYPING':
      case 'READ':
      case 'INVITE':
      case 'INVITE_ACCEPTED':
      case 'INVITE_DECLINED':
      case 'ACK':
      case 'SYNC_REQUEST':
      case 'SYNC_REPLY':
      case 'CALL_OFFER':
      case 'CALL_ANSWER':
      case 'CALL_ICE':
      case 'CALL_REJECT':
      case 'CALL_END':
      case 'GC_INVITE':
      case 'GC_JOINED':
      case 'GC_OFFER':
      case 'GC_ANSWER':
      case 'GC_ICE':
      case 'GC_REJECT':
      case 'GC_END':
      case 'GC_MEMBERS':
      case 'GC_HELLO':
      case 'GROUP_INVITE':
      case 'GROUP_MSG':
      case 'GROUP_MEMBER_ADDED':
      case 'GROUP_MEMBER_LEFT': {
        const to = pkt.to;
        if (!to) break;
        const target = clients.get(to);
        pkt.from = myId;

        if (target && target.readyState === WebSocket.OPEN) {
          target.send(JSON.stringify(pkt));
        } else {
          // User is offline — queue and send FCM push
          const ephemeral = ['TYPING','CALL_ANSWER','CALL_ICE','CALL_REJECT','CALL_END',
            'GC_JOINED','GC_OFFER','GC_ANSWER','GC_ICE','GC_REJECT','GC_END','GC_MEMBERS','GC_HELLO',
            'GROUP_MEMBER_ADDED','GROUP_MEMBER_LEFT'];

          if (!ephemeral.includes(pkt.type)) {
            if (!queue.has(to)) queue.set(to, []);
            const q = queue.get(to);
            pkt._ts = Date.now();
            if (pkt.type === 'CALL_OFFER') pkt._ttl = 60000;
            q.push(pkt);
            if (q.length > MAX_QUEUE) q.shift();

            // Send FCM push notification
            const fcmToken = fcmTokens.get(to);
            if (fcmToken) {
              const senderName = pkt.fromName || myId.slice(0, 8);
              let title, body;
              if (pkt.type === 'CALL_OFFER') {
                title = '📞 Chamada de ' + senderName;
                body = pkt.callType === 'video' ? 'Chamada de vídeo chegando...' : 'Chamada de voz chegando...';
              } else if (pkt.type === 'MSG' || pkt.type === 'IMAGE' || pkt.type === 'AUDIO') {
                title = 'Nexo — ' + senderName;
                body = pkt.type === 'IMAGE' ? '📷 Imagem' : pkt.type === 'AUDIO' ? '🎵 Áudio' : 'Nova mensagem';
              } else if (pkt.type === 'GROUP_MSG') {
                title = 'Grupo — ' + (pkt.groupName || 'Grupo');
                body = (pkt.senderName || senderName) + ': Nova mensagem';
              } else if (pkt.type === 'INVITE') {
                title = 'Nexo — Convite';
                body = senderName + ' quer se conectar com você';
              } else {
                title = 'Nexo';
                body = 'Nova notificação';
              }
              sendFCMNotification(fcmToken, title, body, {
                type: pkt.type,
                from: myId,
                fromName: senderName
              });
            }
          }

          if (myId && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'ACK', id: pkt.id, status: 'queued' }));
          }
        }
        break;
      }

      case 'PING':
        ws.send(JSON.stringify({ type: 'PONG' }));
        break;
    }
  });

  ws.on('close', () => { if (myId) clients.delete(myId); });
  ws.on('error', () => { if (myId) clients.delete(myId); });
});

// Cleanup expired queues every hour
setInterval(() => {
  const now = Date.now();
  for (const [id, q] of queue.entries()) {
    const fresh = q.filter(p => now - p._ts < QUEUE_TTL);
    if (fresh.length === 0) queue.delete(id);
    else queue.set(id, fresh);
  }
}, 60 * 60 * 1000);

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`Nexo relay running on port ${PORT}`);
  console.log(`FCM push notifications: ENABLED`);
});
