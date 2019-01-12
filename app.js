/*
** Cerberus
*/

const child_process = require('child_process');
const fs = require('fs');
const express = require('express');
const cookie = require('cookie');
const mongo = require('mongodb').MongoClient;
const crypto = require('crypto');
const secp256k1 = require('secp256k1');
const otp = require('otplib').authenticator;
const app = express();

var server;
var db, users, sessions;
var lastSessionsCheck = 0;

var socket;
if (process.env.NODE_ENV === 'test')
  socket = 3080;
else {
  socket = __dirname + '/run/socket';

  process.umask(0);
  if (fs.existsSync(socket)) {
    if (child_process.spawnSync('/bin/fuser', [ socket ]).stdout.toString()) {
      console.error("Socket already used...");
      process.exit(1);
    }
    fs.unlinkSync(socket);
  }
}


app.use(express.json());

app.use(function (req, res, next) {
  var dt = Date.now();

  if ((dt - lastSessionsCheck) >= 60) {
    lastSessionsCheck = dt;
    sessions.deleteMany({ lastUsed: { $lte: dt - (1000 * 3600 * 24 * 31) } });
  }

  let token = cookie.parse(req.headers.cookie || '').cerberus
  sessions.findOne({ token: token }).then(function (s) {
    if (s) {
      req.session = s;
      sessions.updateOne({ _id: s._id }, { $set: { lastUsed: dt } });
    }
    next();
  });
});


app.get('/auth', function(req, res) {
  res.sendStatus(req.session ? 204 : 401);
});


app.get('/api/info', function(req, res) {
  res.json(req.session ? { name: req.session.name, pseudo: req.session.pseudo, token: req.session.token } : {});
});


app.post('/api/prelogin', function(req, res) {
  if ((req.body.l === undefined) || (typeof req.body.l !== 'string'))
    return res.sendStatus(400);

  c = crypto.randomBytes(32).toString('hex');
  users.updateOne({ pseudo: req.body.l }, {$set: {c: c}});
  res.json({ c: c });
});

app.post('/api/login', function(req, res) {
  if ((req.body.l === undefined) || (typeof req.body.l !== 'string') ||
      (req.body.r === undefined) || (typeof req.body.r !== 'string') ||
      (req.body.g === undefined) || (typeof req.body.g !== 'string'))
    return res.sendStatus(400);

  users.findOne({ pseudo: req.body.l }).then(function (u) {
    if (!u)
      return res.sendStatus(401);

    users.updateOne({ pseudo: u.pseudo }, { $unset: { c: true } });

    if (! secp256k1.verify(Buffer.from(u.c, 'hex'), Buffer.from(req.body.r, 'hex'), Buffer.from(u.pkey, 'hex'))) {
      console.log('Invalid password for user ' + u.pseudo);
      return res.sendStatus(401);
    }
    if (! otp.check(req.body.g, u.gotp)) {
      console.log('Invalid TOTP code for user ' + u.pseudo);
      return res.sendStatus(401);
    }

    if (req.session)
      sessions.deleteOne({ _id: req.session._id });

    let token = crypto.randomBytes(32).toString('hex');
    let ip = req.headers['x-real-ip'] || req.connection.remoteAddress;
    let ua = req.headers['user-agent'];
    sessions.insertOne({ name: u.name, pseudo: u.pseudo, token: token, ip: ip, ua: ua, lastUsed: Date.now() }).then(function () {
      res.json({ name: u.name, pseudo: u.pseudo, token: token });
    });
  });
});

app.get('/api/logout', function(req, res) {
  if (req.session)
    sessions.deleteOne({ _id: req.session._id });
  res.sendStatus(204);
});


app.post('/api/geninfo', function(req, res) {
  if ((req.body.gid === undefined) || (typeof req.body.gid !== 'string'))
    return res.sendStatus(400);

  db.collection('g_users').findOne({ gid: req.body.gid }).then(function (gu) {
    if (! gu)
      res.sendStatus(401);
    else
      res.json({ pseudo: gu.pseudo, qrcode: otp.keyuri(gu.pseudo, 'cerberus', gu.gotp) });
  });
});

app.post('/api/generate', function(req, res) {
  if ((req.body.gid === undefined) || (typeof req.body.gid !== 'string') ||
      (req.body.g === undefined) || (typeof req.body.g !== 'string') ||
      (req.body.k === undefined) || (typeof req.body.k !== 'string'))
    return res.sendStatus(400);

  db.collection('g_users').findOne({ gid: req.body.gid }).then(function (gu) {
    if (! gu)
      return res.sendStatus(401);
    if (! otp.check(req.body.g, gu.gotp))
      return res.status(403).json({ error: 'Invalid G-OTP code..'});

    if (req.session)
      return res.sendStatus(400);

    db.collection('g_users').deleteOne({ gid: req.body.gid });
    users.insertOne({ name: gu.name, pseudo: gu.pseudo, pkey: req.body.k, gotp: gu.gotp });

    let token = crypto.randomBytes(32).toString('hex');
    let ip = req.headers['x-real-ip'] || req.connection.remoteAddress;
    let ua = req.headers['user-agent'];
    sessions.insertOne({ name: gu.name, pseudo: gu.pseudo, token: token, ip: ip, ua: ua, lastUsed: Date.now() }).then(function () {
      res.json({ name: gu.name, pseudo: gu.pseudo, token: token });
    });
  });
});


app.get('/api/list', function(req, res) {
  if (! req.session)
    return res.sendStatus(401);

  sessions.find({ pseudo: req.session.pseudo }).project({ ip: 1, ua: 1, lastUsed: 1 }).toArray().then(function (sl) {
    sl[sl.findIndex(function (el) { return el._id.equals(req.session._id) })].current = true;
    res.json(sl);
  });
});

app.post('/api/remove', function(req, res) {
  if (! req.session)
    return res.sendStatus(401);

  if ((req.body.sid === undefined) || (typeof req.body.sid !== 'string'))
    return res.sendStatus(400);

  sessions.deleteOne({ _id: req.body.sid, pseudo: req.session.pseudo })
  res.sendStatus(204);
});

app.get('/api/flush', function(req, res) {
  if (! req.session)
    return res.sendStatus(401);

  sessions.deleteMany({ pseudo: req.session.pseudo, _id: { $ne: req.session._id } });
  res.sendStatus(204);
});


app.use(function(err, req, res, next) {
  console.error(err.stack);
  res.status(500).json({ error: 'Erreur interne..' });
});


mongo.connect('mongodb://localhost:27017', { useNewUrlParser: true }).then(function(client) {
  db = client.db('cerberus');
  users = db.collection('users');
  sessions = db.collection('sessions');

  otp.options = {
    encoding: 'hex',
    epoch: null,
    step: 30,
    window: 1
  };

  server = require('http').createServer(app);
  server.listen(socket, function () {
    console.log("App listening on '" + socket + "'.");
    process.send('ready');
  });

  process.on('SIGINT', function () {
    console.log('Graceful shutdown..');
    if (process.env.NODE_ENV !== 'test')
      fs.unlinkSync(socket);
    server.close(function(err) {
      if (err) {
        console.error(err);
        process.exit(1);
      }
    });
    client.close();
  });
});
