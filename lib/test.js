const sinon = require('sinon');

const crypto = require('crypto');
const secp256k1 = require('secp256k1');
const { authenticator: totp } = require('otplib');
const http = require('http');

process.env.NODE_ENV = 'test';

const createID = () => {
  return {
    id: crypto.randomBytes(12).toString('hex'),
    equals: function equals (id2) { return this.id === id2.id; },
    toString: function toString () { return this.id; }
  };
};

const $ = {
  mdb: { },

  reset: () => {
    sinon.reset();

    for (let col in $.mdb)
      if (Object.prototype.hasOwnProperty.call($.mdb, col)) {
        $.mdb[col].deleteOne.resolves();
        $.mdb[col].deleteMany.resolves();
        $.mdb[col].find.returns({ project: _p => ({ toArray: () => Promise.resolve([]) }) });
        $.mdb[col].findOne.resolves();
        $.mdb[col].insertOne.resolves();
        $.mdb[col].updateOne.resolves();
      }

    $.users = { };
  },

  prvFromPassword: (pseudo, password) => {
    let priv = Buffer.alloc(32);
    crypto.createHash('ripemd160').update(crypto.pbkdf2Sync(password, pseudo, 42, 32, 'sha256')).digest().copy(priv, 12);
    return priv;
  },
  signature: (challenge, pseudo, password) => {
    if (password === undefined)
      // eslint-disable-next-line no-param-reassign
      ({ password } = $.users[pseudo]);

    return secp256k1.sign(Buffer.from(challenge, 'hex'), $.prvFromPassword(pseudo, password)).signature;
  },

  addUser: (pseudo, name, password) => {
    let pkey = secp256k1.publicKeyCreate($.prvFromPassword(pseudo, password)).toString('hex');
    let gotp = totp.generateSecret();
    let user = { _id: createID(), name: name, pseudo: pseudo, pkey: pkey, gotp: gotp };

    $.users[pseudo] = { user: user, password: password, gotp: gotp, sessions: [ ] };
    $.mdb.users.findOne.withArgs({ pseudo: pseudo }).resolves(user);
    $.mdb.sessions.find.withArgs({ pseudo: pseudo }).returns({ project: () => { return { toArray: () => Promise.resolve($.users[pseudo].sessions) }; } });
    return user;
  },
  genUserC: pseudo => {
    let c = crypto.randomBytes(32).toString('hex');

    $.users[pseudo].user.c = c;
    return c;
  },
  addSession: pseudo => {
    let token = crypto.randomBytes(32).toString('hex');
    let { user } = $.users[pseudo];
    let session = { _id: createID(), name: user.name, pseudo: pseudo, token: token, lastUsed: Date.now() };

    $.users[pseudo].sessions.push(session);
    $.mdb.sessions.findOne.withArgs({ token: token }).resolves(session);
    return session;
  },
  addGUser: (pseudo, name, password = '') => {
    let gotp = totp.generateSecret();
    let gid = crypto.randomBytes(32).toString('hex');
    let guser = { _id: createID(), gid: gid, pseudo: pseudo, name: name, gotp: gotp };

    $.users[pseudo] = { guser: guser, password: password, gotp: gotp };
    $.mdb.g_users.findOne.withArgs({ gid: gid }).resolves(guser);
    return guser;
  },
  getGUserPKey: pseudo => {
    return secp256k1.publicKeyCreate($.prvFromPassword(pseudo, $.users[pseudo].password)).toString('hex');
  },
  getUserOTP: (pseudo, delta = 0) => {
    let optsbk = totp.options;
    totp.options = { epoch: (Date.now() / 1000) + delta, step: 30 };
    let token = totp.generate($.users[pseudo].gotp);
    totp.options = optsbk;
    return token;
  },

  get: (path, token = '') => {
    return new Promise((resolve, reject) => {
      http.get({ port: 3080, path: path, headers: { 'Cookie': 'cerberus=' + token } }, res => {
        res.body = '';
        res
          .on('data', chunk => { res.body += chunk; })
          .on('error', reject)
          .on('end', () => {
            if (res.statusCode === 200)
              res.body = JSON.parse(res.body);
            resolve(res);
          });
      });
    });
  },
  post: (path, prm, token = '') => {
    return new Promise((resolve, reject) => {
      let data = JSON.stringify(prm);
      let headers = {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
        'Cookie': 'cerberus=' + token
      };

      http.request({ port: 3080, method: 'POST', path: path, headers: headers }, res => {
        res.body = '';
        res
          .on('data', chunk => { res.body += chunk; })
          .on('error', reject)
          .on('end', () => {
            if (res.statusCode === 200)
              res.body = JSON.parse(res.body);
            resolve(res);
          });
      }).end(data);
    });
  }
};


// eslint-disable-next-line array-element-newline
for (let col of [ 'users', 'sessions', 'g_users' ])
  $.mdb[col] = {
    deleteOne: sinon.stub(),
    deleteMany: sinon.stub(),
    find: sinon.stub(),
    findOne: sinon.stub(),
    insertOne: sinon.stub(),
    updateOne: sinon.stub()
  };
$.reset();


require('mongodb').MongoClient.connect = () => {
  return Promise.resolve({ db: () => ({ collection: collection => $.mdb[collection] }) });
};


module.exports = $;
