#!/usr/bin/node

const args = process.argv.slice(2);

const cmds = {
  'list': {
    comment: 'List users',
    prm: [ ],
    proc: function(db) {
      return db.find().toArray().then(function(items) {
        console.log(items);
      });
    }
  },

  'otpcode': {
    comment: 'Show current TOTP code of a specific user',
    prm: [ 'pseudo' ],
    proc: function(db, pseudo) {
      return db.findOne({ pseudo: pseudo }).then(function(user) {
        console.log(require('otplib').authenticator.generate(user.gotp));
      });
    }
  },

  'checkpasswd': {
    comment: 'Check a specific user\'s password',
    prm: [ 'pseudo', 'passwd' ],
    proc: function(db, pseudo, passwd) {
      return db.findOne({ pseudo: pseudo }).then(function(user) {
        const crypto = require('crypto');
        const ec = require('secp256k1');

        // Server-side: GET /api/prelogin(pseudo) => c
        c = crypto.randomBytes(256 / 8);
        console.log("c: " + c.toString('hex'));

        // Client-side: generate s = sign(c)
        let key = Buffer.alloc(32);
        crypto.createHash('ripemd160').update(crypto.pbkdf2Sync(passwd, pseudo, 42, 32, 'sha256')).digest().copy(key, 12);
        s = ec.sign(c, key).signature;
        console.log("s: " + s.toString('hex'));

        // Server-side: GET /api/login(pseudo, s)
        console.log(ec.verify(c, s, Buffer.from(user.pkey, 'hex')));
      }).catch(function() {
        throw "Unknown user..";
      });
    }
  }

};


var cmd;
if ((args.length == 0) || ((cmd = cmds[args[0]]) === undefined) || (args.length != cmd.prm.length + 1)) {
  console.log("users.js <cmd> [<param> ..]");
  for (key in cmds)
    console.log(key + ": " + cmds[key].comment);
  process.exit(1);
} else {
  require('mongodb').MongoClient.connect('mongodb://localhost:27017', { useNewUrlParser: true }).then(function(client) {
    args[0] = client.db('cerberus').collection('users');
    cmd.proc.apply(null, args).then(function() {
      client.close();
      process.exit();
    }).catch(function(err) {
      console.log(err);
      client.close();
      process.exit(2);
    });
  });
};
