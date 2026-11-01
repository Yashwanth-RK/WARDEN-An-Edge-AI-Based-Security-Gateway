
// WARDEN Dashboard Server
// Live mode:
// set SENDER_PORT=COM9
// set RECEIVER_PORT=COM5
// node server.js
//
// Demo mode:
// node server.js

const http = require('http');
const fs = require('fs');
const path = require('path');

const clients = new Set();
const sd = {};
const rx = {};
const ports = {};

// ---------------- SSE EVENT DELIVERY ----------------

const emit = o => {
  const message = `data:${JSON.stringify(o)}\n\n`;

  for (const client of clients) {
    if (!client.destroyed && client.writable) {
      client.write(message);
    }
  }
};

const num = l => parseFloat(l.split(':')[1]);

// ---------------- SENDER AND RECEIVER PARSERS ----------------

const parsers = {
  sender(l) {
    if (l.startsWith('Reading #:')) {
      sd.n = +l.split(':')[1];
    } else if (l.startsWith('Temperature:')) {
      sd.temp = num(l);
    } else if (l.startsWith('Humidity:')) {
      sd.hum = num(l);

      emit({
        t: 'sender',
        n: sd.n,
        temp: sd.temp,
        hum: sd.hum
      });
    } else if (l.startsWith('[HALT]')) {
      emit({ t: 'halt', v: true });
    } else if (l.startsWith('[RESUME]')) {
      emit({ t: 'halt', v: false });
    } else if (l.startsWith('[ERROR]')) {
      emit({ t: 'log', src: 'SND', line: l });
    }
  },

  receiver(l) {
    if (/^(SENT|MITM)\|/.test(l)) {
      const f = l.split('|');

      rx.src = f[0];
      rx.n = f[1];

      emit({
        t: 'rxraw',
        src: rx.src,
        n: rx.n
      });
    } else if (l.startsWith('Temperature:')) {
      rx.temp = num(l);
    } else if (l.startsWith('Humidity:')) {
      rx.hum = num(l);

      emit({
        t: 'rx',
        src: rx.src,
        n: rx.n,
        temp: rx.temp,
        hum: rx.hum
      });
    } else if (l.startsWith('Alert number:')) {
      rx.an = +l.split(':')[1];
    } else if (l.startsWith('Detection:')) {
      emit({
        t: 'alert',
        n: rx.an,
        reason: l.slice(10).trim()
      });
    } else if (l.includes('IDS CUTOFF')) {
      emit({ t: 'cutoff' });
    } else if (
      l.startsWith('[MANUAL RESET]') ||
      l.startsWith('[RESUME] IDS')
    ) {
      emit({ t: 'resume' });
    }
  }
};

// ---------------- SERIAL CONNECTIONS ----------------

const cfg = {
  sender: process.env.SENDER_PORT,
  receiver: process.env.RECEIVER_PORT
};

const DEMO = !cfg.sender && !cfg.receiver;

if (!DEMO) {
  const { SerialPort, ReadlineParser } = require('serialport');

  for (const [role, portName] of Object.entries(cfg)) {
    if (!portName) continue;

    const serial = new SerialPort({
      path: portName,
      baudRate: 115200
    });

    const parser = serial.pipe(
      new ReadlineParser({ delimiter: '\n' })
    );

    parser.on('data', data => {
      const line = data.trim();

      if (line) {
        parsers[role](line);
      }
    });

    serial.on('error', error => {
      console.error(`[${role}]`, error.message);
    });

    ports[role] = serial;

    console.log(`${role} <- ${portName}`);
  }
}

// ---------------- DEMO SIMULATOR ----------------

let dn = 0;
let dAlerts = 0;
let dCut = false;

if (DEMO) {
  setInterval(() => {
    if (dCut) return;

    const temp = +(27 + Math.random() * 2).toFixed(1);
    const hum = +(55 + Math.random() * 5).toFixed(1);

    dn++;

    emit({
      t: 'sender',
      n: dn,
      temp,
      hum
    });

    setTimeout(() => {
      emit({
        t: 'rxraw',
        src: 'SENT',
        n: dn
      });

      emit({
        t: 'rx',
        src: 'SENT',
        n: dn,
        temp,
        hum
      });
    }, 700);
  }, 2000);
}

// ---------------- DEMO ATTACK ----------------

function demoAttack() {
  if (dCut) return;

  dAlerts++;

  emit({
    t: 'rxraw',
    src: 'MITM',
    n: dAlerts
  });

  emit({
    t: 'rx',
    src: 'MITM',
    n: dAlerts,
    temp: 85,
    hum: 5
  });

  emit({
    t: 'alert',
    n: dAlerts,
    reason: dAlerts === 1
      ? 'Sensor value anomaly'
      : 'MITM demonstration packet'
  });

  if (dAlerts >= 2) {
    dCut = true;

    emit({ t: 'cutoff' });
    emit({ t: 'halt', v: true });
  }
}

// ---------------- HTTP SERVER ----------------

const server = http.createServer((req, res) => {

  // SSE connection
  if (req.url === '/events') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache, no-transform',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no'
    });

    // Flush headers immediately.
    res.flushHeaders();

    // Disable TCP Nagle buffering.
    if (res.socket) {
      res.socket.setNoDelay(true);
    }

    // Preserve the original hello event.
    res.write(
      `data:${JSON.stringify({
        t: 'hello',
        demo: DEMO
      })}\n\n`
    );

    clients.add(res);

    console.log(
      `[SSE] Client connected. Active clients: ${clients.size}`
    );

    req.on('close', () => {
      clients.delete(res);

      console.log(
        `[SSE] Client disconnected. Active clients: ${clients.size}`
      );
    });

    return;
  }

  // ---------------- MANUAL CUTOFF / RESUME ----------------

  if (
    req.method === 'POST' &&
    req.url === '/api/cutoff'
  ) {
    let body = '';

    req.on('data', chunk => {
      body += chunk;
    });

    req.on('end', () => {
      let on;

      try {
        on = JSON.parse(body || '{}').on;
      } catch {
        res.writeHead(400);
        return res.end('Invalid JSON');
      }

      if (DEMO) {
        dCut = Boolean(on);

        if (on) {
          emit({ t: 'cutoff' });
          emit({ t: 'halt', v: true });
        } else {
          dAlerts = 0;

          emit({ t: 'resume' });
          emit({ t: 'halt', v: false });
        }
      } else if (
        ports.receiver &&
        ports.receiver.isOpen
      ) {
        ports.receiver.write(on ? 'H\n' : 'R\n');
      } else {
        console.error(
          '[CONTROL] Receiver serial port unavailable'
        );
      }

      res.writeHead(200, {
        'Content-Type': 'text/plain'
      });

      res.end('ok');
    });

    return;
  }

  // ---------------- DEMO ATTACK BUTTON ----------------

  if (
    DEMO &&
    req.method === 'POST' &&
    req.url === '/api/demo/attack'
  ) {
    demoAttack();

    res.writeHead(200, {
      'Content-Type': 'text/plain'
    });

    return res.end('ok');
  }

  // ---------------- DASHBOARD FILES ----------------

  const file = req.url
    .split('?')[0]
    .replace(/\.\./g, '');

  const filePath = path.join(
    __dirname,
    'public',
    file === '/' ? 'index.html' : file
  );

  fs.readFile(filePath, (error, data) => {
    if (error) {
      res.writeHead(404);
      return res.end('not found');
    }

    res.writeHead(200, {
      'Content-Type': filePath.endsWith('.js')
        ? 'text/javascript'
        : 'text/html',
      'Cache-Control': 'no-cache'
    });

    res.end(data);
  });
});

// ---------------- SSE HEARTBEAT ----------------

// Keep SSE connections alive without sending dashboard events.
const heartbeat = setInterval(() => {
  for (const client of clients) {
    if (!client.destroyed && client.writable) {
      client.write(': heartbeat\n\n');
    }
  }
}, 10000);

// ---------------- CLEANUP ----------------

server.on('close', () => {
  clearInterval(heartbeat);

  for (const client of clients) {
    client.end();
  }

  for (const serial of Object.values(ports)) {
    if (serial.isOpen) {
      serial.close();
    }
  }
});

// ---------------- START SERVER ----------------

server.listen(3000, () => {
  console.log('====================================');
  console.log('WARDEN Secure Sensor Link Dashboard');
  console.log('Dashboard: http://localhost:3000');
  console.log(`Mode: ${DEMO ? 'DEMO' : 'LIVE SERIAL'}`);

  if (!DEMO) {
    console.log('Sender port:', cfg.sender || 'Not configured');
    console.log('Receiver port:', cfg.receiver || 'Not configured');
  }

  console.log('====================================');
});
