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
  private_key: `-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDwm0KOe7Si2qiy\n3ige6v9g7I9TbNes0ApeWbtLa8PJRuOA2LBUDdbOoyGP3Q1cxPyXbW45WAipmUJI\ng7u1saKwKg4FDUUFoTpSG7phZnT+6irLNPMbRxG9PEW8ZiisvcSQS4tLxDxD5rUa\nrYLFfJxtLaWkVMvt9AdxlIYQFwdXud0Fsu91BovdU7e1ugd8QRcTHEDRT0Hu8K3p\nQ8WNuStE0KshE0hDqm1tLdKArlgsvEU3ul8vjf4bvFBMQhLA5Q0xzNELAWbs7uNh\nFkwunKQBe8W+0tlQr6Qxk/vgXAmU3stx/I/SmNf7SqPKO/YjxuR+85/wAr0HSsp+\nGeCTogF9AgMBAAECggEADgrdtaT6JqwQ1E77c/cpUaM/fTIOcgdP/PA16mxfHaLt\nxGIWg8gCqAY6KfmP3gDK24f3OtEMwQs7ugbi4HM+MxO37usL7XdwCNqV7uPU2GDb\nKlzMLc92H/+ByWxZRjWqyx9269nc3jtQ3r5O3M74Q+CkuM8lz3I33Ko7WyU2Qulu\nMmLQBEIYx0RR9cEMun776UqqIeKqShh5eBr7jECAOzvsVbXvFRuIpS2tkdWay7EU\ncOiYMJZq6KHlIFhCc6HkspaICGwc8Gs7d1mfSLktHD4YYnL1w7TXDnciZbMOfXxy\n6xu3V/uUtwXbiv3HgPOBdslwgsx1yMru0EL8qDPlYQKBgQD8krODryOWy4B5AScQ\nn7De+CN5Q86c9df+tIBLh3vKh80pAhEH6Pe+dwAOG+b6QIwBuzZrteXMmnLtrha2\n7n+wUeTMz0O47i4dCDaKfzV0MLA4u+TPqV20qWCX9dJ130yEHjbDSIG8CpJ6VjZr\nVGsy8jkh9kW5zPgxBbZzMz5qoQKBgQDz3v5YcT2u9ubYf7uHxa0LS1cODGz438Sq\nrtoWrfv6SAWKGV5kzknpHWOW/gZPnm+UzQ6lFTuwjPwNmH5akvwnwv6Amk151/1F\nI8PdqTFDiv8C2s4H9UOBg0p8D5u656IaSn0Cvp+11oAde6FLEQP0XtaG3Hmudhqm\ngi3VUQwlXQKBgQCfDedcexOHZ9oc2Zv3PQlOMKduO0RG1g7SiGrupYBQd5q8Q1/k\nQlKZsCjpuaqIV9OTV4ka5W60nWLYyLPnOWRR7hCO5cs5D00c3Uozh45rACpJYBHk\nsDyhg7SfnZ+OuTNfVAOakPOaLnI19krI5l2ntKBEAenA6xI1FOrjuxaIYQKBgFcj\nMax2Yfz3ecqX8XD0//zOIcACTpmqkwIN0h1Sc3udamVK5UCNuTkTaDdWcvjV+ran\ngnkYGijeZ12QRG2moXSvpvJasB4+P+AJhH3aa6DftHjXp9COIV3QhLfJd/KTu4c7\nYGmvpS97AnIGb757yPbzQCIV+2CMEL+4OhpDiFx9AoGAOLIKXfIqXsDKE+kRxqsz\nCcdCBSz7Iw9ph/U8mwY9CvcJ/LFHGuoiuDLCgStpSSxTc6/Ba/2AKaWf2UeCyT2F\nAMU794tg8MgPhUzdimMkLxBZ/l8nyvgxBF/MmixznBq1y28c0djaxleSzIXFJRQH\nu4lgMluqvOAOoJd7FMkcqCk=\n-----END PRIVATE KEY-----\n`
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
