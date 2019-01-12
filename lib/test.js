const sinon = require('sinon');

const crypto = require('crypto');
const secp256k1 = require('secp256k1');
const otplib = require('otplib');
const totp = otplib.authenticator;
const http = require('http');

process.env.NODE_ENV = 'test';

function createID() {
  return {
    id: crypto.randomBytes(12).toString('hex'),
    equals: function (id2) { return this.id === id2.id },
    toString: function () { return this.id }
  };
}

const $ = {
  mdb: { },

  reset: function() {
    sinon.reset();

    for (col in $.mdb) {
      $.mdb[col].deleteOne.resolves(),
      $.mdb[col].deleteMany.resolves(),
      $.mdb[col].find.returns({
        project: function (p) { return {
          toArray: function () { return Promise.resolve([]) }
        } }
      }),
      $.mdb[col].findOne.resolves(),
      $.mdb[col].insertOne.resolves(),
      $.mdb[col].updateOne.resolves()
    };

    $.users = { };
  },

  prvFromPassword: function (pseudo, password) {
    let priv = Buffer.alloc(32);
    crypto.createHash('ripemd160').update(crypto.pbkdf2Sync(password, pseudo, 42, 32, 'sha256')).digest().copy(priv, 12);
    return priv;
  },
  signature: function (challenge, pseudo, password = undefined) {
    if (password === undefined)
      password = $.users[pseudo].password;

    return secp256k1.sign(Buffer.from(challenge, 'hex'), $.prvFromPassword(pseudo, password)).signature;
  },

  addUser: function (pseudo, name, password) {
    let pkey = secp256k1.publicKeyCreate($.prvFromPassword(pseudo, password)).toString('hex');
    let gotp = totp.generateSecret();
    user = { _id: createID(), name: name, pseudo: pseudo, pkey: pkey, gotp: gotp };

    $.users[pseudo] = { user: user, password: password, gotp: gotp, sessions: [ ] };
    $.mdb.users.findOne.withArgs({ pseudo: pseudo }).resolves(user);
    $.mdb.sessions.find.withArgs({ pseudo: pseudo }).returns({
      project: function (p) { return {
        toArray: function () { return Promise.resolve($.users[pseudo].sessions) }
      } }
    });
    return user;
  },
  genUserC: function (pseudo) {
    return $.users[pseudo].user.c = crypto.randomBytes(32).toString('hex');
  },
  addSession: function (pseudo) {
    let token = crypto.randomBytes(32).toString('hex');
    let user = $.users[pseudo].user;
    let session = { _id: createID(), name: user.name, pseudo: pseudo, token: token, lastUsed: Date.now() };

    $.users[pseudo].sessions.push(session);
    $.mdb.sessions.findOne.withArgs({ token: token }).resolves(session);
    return session;
  },
  addGUser: function (pseudo, name, password = '') {
    let gotp = totp.generateSecret();
    let gid = crypto.randomBytes(32).toString('hex');
    let guser = { _id: createID(), gid: gid, pseudo: pseudo, name: name, gotp: gotp };

    $.users[pseudo] = { guser: guser, password: password, gotp: gotp };
    $.mdb.g_users.findOne.withArgs({ gid: gid }).resolves(guser);
    return guser;
  },
  getGUserPKey: function (pseudo) {
    return secp256k1.publicKeyCreate($.prvFromPassword(pseudo, $.users[pseudo].password)).toString('hex');
  },
  getUserOTP: function (pseudo, delta = 0) {
    let optsbk = totp.options;
    totp.options = { epoch: (Date.now() / 1000) + delta, step: 30 };
    let token = totp.generate($.users[pseudo].gotp);
    totp.options = optsbk;
    return token;
  },

  get: function (path, token = '') {
    return new Promise(function (resolve, reject) {
      http.get({ port: 3080, path: path, headers: { 'Cookie': 'cerberus=' + token } }, function(res) {
        res.body = '';
        res
          .on('data', function (chunk) { res.body += chunk })
          .on('error', reject)
          .on('end', function () {
            if (res.statusCode == 200)
              res.body = JSON.parse(res.body);
            resolve(res);
          });
      });
    });
  },
  post: function (path, prm, token = '') {
    return new Promise(function (resolve, reject) {
      let data = JSON.stringify(prm);
      let headers = {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
        'Cookie': 'cerberus=' + token
      };

      http.request({ port: 3080, method: 'POST', path: path, headers: headers }, function (res) {
        res.body = '';
        res
          .on('data', function (chunk) { res.body += chunk })
          .on('error', reject)
          .on('end', function () {
            if (res.statusCode == 200)
              res.body = JSON.parse(res.body);
            resolve(res);
          });
      }).end(data);
    });
  }
};


for (col of ['users', 'sessions', 'g_users'])
  $.mdb[col] = {
    deleteOne: sinon.stub(),
    deleteMany: sinon.stub(),
    find: sinon.stub(),
    findOne: sinon.stub(),
    insertOne: sinon.stub(),
    updateOne: sinon.stub()
  };
$.reset();


require('mongodb').MongoClient.connect = function (url, options) {
  return Promise.resolve({
    db: function(base) {
      return {
        collection: function (collection) { return $.mdb[collection] }
      };
    }
  });
};


module.exports = $;
