/*
** Cerberus
*/

const { spawnSync } = require('child_process');
const { existsSync, unlinkSync } = require('fs');
const express = require('express');
const { parse } = require('cookie');
const { MongoClient } = require('mongodb');
const { randomBytes } = require('crypto');
const { verify, signatureNormalize } = require('secp256k1');
const { authenticator: totp } = require('otplib');
const path = require('path');

var server;
var db, users, sessions;
var lastSessionsCheck = 0;

var socket;
if (process.env.NODE_ENV === 'test')
  socket = 3080;
else {
  socket = path.join(__dirname, 'run', 'socket');

  process.umask(0);
  if (existsSync(socket)) {
    if (spawnSync('/bin/fuser', [ socket ]).stdout.toString()) {
      console.error('Socket already used...');
      process.exit(1);
    }
    unlinkSync(socket);
  }
}


const app = express();

app.use(express.json());

app.use((req, _res, next) => {
  var dt = Date.now();

  if ((dt - lastSessionsCheck) >= 60 * 1000) {
    lastSessionsCheck = dt;
    sessions.deleteMany({ lastUsed: { $lte: dt - (1000 * 3600 * 24 * 31) } });
  }

  let token = parse(req.headers.cookie || '').cerberus;
  sessions.findOne({ token: token }).then(s => {
    if (s) {
      req.session = s;
      sessions.updateOne({ _id: s._id }, { $set: { lastUsed: dt } });
    }
    next();
  });
});


app.get('/auth', (req, res) => {
  res.sendStatus(req.session ? 204 : 401);
});


app.get('/api/info', (req, res) => {
  res.json(req.session ? { name: req.session.name, pseudo: req.session.pseudo, token: req.session.token } : {});
});


app.post('/api/prelogin', (req, res) => {
  if ((req.body.l === undefined) || (typeof req.body.l !== 'string'))
    return res.sendStatus(400);

  let c = randomBytes(32).toString('hex');
  users.updateOne({ pseudo: req.body.l }, {$set: {c: c}});
  res.json({ c: c });
});

app.post('/api/login', (req, res) => {
  if ((req.body.l === undefined) || (typeof req.body.l !== 'string') ||
      (req.body.r === undefined) || (typeof req.body.r !== 'string') ||
      (req.body.g === undefined) || (typeof req.body.g !== 'string'))
    return res.sendStatus(400);

  users.findOne({ pseudo: req.body.l }).then(u => {
    if (! u)
      return res.sendStatus(401);

    users.updateOne({ pseudo: u.pseudo }, { $unset: { c: true } });

    if (! verify(Buffer.from(u.c, 'hex'), signatureNormalize(Buffer.from(req.body.r, 'hex')), Buffer.from(u.pkey, 'hex'))) {
      console.log('Invalid password for user ' + u.pseudo);
      return res.sendStatus(401);
    }
    if (! totp.check(req.body.g, u.gotp)) {
      console.log('Invalid TOTP code for user ' + u.pseudo);
      return res.sendStatus(401);
    }

    if (req.session)
      sessions.deleteOne({ _id: req.session._id });

    let token = randomBytes(32).toString('hex');
    let ip = req.headers['x-real-ip'] || req.connection.remoteAddress;
    let ua = req.headers['user-agent'];
    sessions.insertOne({ name: u.name, pseudo: u.pseudo, token: token, ip: ip, ua: ua, lastUsed: Date.now() }).then(() => {
      res.json({ name: u.name, pseudo: u.pseudo, token: token });
    });
  });
});

app.get('/api/logout', (req, res) => {
  if (req.session)
    sessions.deleteOne({ _id: req.session._id });
  res.sendStatus(204);
});


app.post('/api/geninfo', (req, res) => {
  if ((req.body.gid === undefined) || (typeof req.body.gid !== 'string'))
    return res.sendStatus(400);

  db.collection('g_users').findOne({ gid: req.body.gid }).then(gu => {
    if (! gu)
      res.sendStatus(401);
    else
      res.json({ pseudo: gu.pseudo, qrcode: totp.keyuri(gu.pseudo, 'cerberus', gu.gotp) });
  });
});

app.post('/api/generate', (req, res) => {
  if ((req.body.gid === undefined) || (typeof req.body.gid !== 'string') ||
      (req.body.g === undefined) || (typeof req.body.g !== 'string') ||
      (req.body.k === undefined) || (typeof req.body.k !== 'string'))
    return res.sendStatus(400);

  db.collection('g_users').findOne({ gid: req.body.gid }).then(gu => {
    if (! gu)
      return res.sendStatus(401);
    if (! totp.check(req.body.g, gu.gotp))
      return res.status(403).json({ error: 'Invalid G-OTP code..'});

    if (req.session)
      return res.sendStatus(400);

    db.collection('g_users').deleteOne({ gid: req.body.gid });
    users.insertOne({ name: gu.name, pseudo: gu.pseudo, pkey: req.body.k, gotp: gu.gotp });

    let token = randomBytes(32).toString('hex');
    let ip = req.headers['x-real-ip'] || req.connection.remoteAddress;
    let ua = req.headers['user-agent'];
    sessions.insertOne({ name: gu.name, pseudo: gu.pseudo, token: token, ip: ip, ua: ua, lastUsed: Date.now() }).then(() => {
      res.json({ name: gu.name, pseudo: gu.pseudo, token: token });
    });
  });
});


app.get('/api/list', (req, res) => {
  if (! req.session)
    return res.sendStatus(401);

  sessions.find({ pseudo: req.session.pseudo }).project({ ip: 1, ua: 1, lastUsed: 1 }).toArray().then(sl => {
    sl[sl.findIndex(el => { return el._id.equals(req.session._id); })].current = true;
    res.json(sl);
  });
});

app.post('/api/remove', (req, res) => {
  if (! req.session)
    return res.sendStatus(401);

  if ((req.body.sid === undefined) || (typeof req.body.sid !== 'string'))
    return res.sendStatus(400);

  sessions.deleteOne({ _id: req.body.sid, pseudo: req.session.pseudo });
  res.sendStatus(204);
});

app.get('/api/flush', (req, res) => {
  if (! req.session)
    return res.sendStatus(401);

  sessions.deleteMany({ pseudo: req.session.pseudo, _id: { $ne: req.session._id } });
  res.sendStatus(204);
});


app.use((err, req, res) => {
  console.error(req, err.stack);
  res.status(500).json({ error: 'Erreur interne..' });
});


MongoClient.connect('mongodb://localhost:27017', { useNewUrlParser: true }).then(client => {
  db = client.db('cerberus');
  users = db.collection('users');
  sessions = db.collection('sessions');

  totp.options = {
    encoding: 'hex',
    epoch: null,
    step: 30,
    window: 1
  };

  server = require('http').createServer(app);
  server.listen(socket, () => {
    console.log('App listening on "' + socket + '".');
    process.send('ready');
  });

  process.on('SIGINT', () => {
    console.log('Graceful shutdown..');
    if (process.env.NODE_ENV !== 'test')
      unlinkSync(socket);
    server.close(err => {
      if (err) {
        console.error(err);
        process.exit(1);
      }
    });
    client.close();
  });
});
