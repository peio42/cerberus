#!/usr/bin/node

const cmds = {
  'list': {
    comment: 'List users',
    prm: [ ],
    proc: db => {
      return db.users.find().toArray().then(items => {
        console.log(items);
      });
    }
  },

  'otpcode': {
    comment: 'Show current TOTP code of a specific user',
    prm: [ 'pseudo' ],
    proc: (db, pseudo) => {
      return db.users.findOne({ pseudo }).then(user => {
        console.log(require('otplib').authenticator.generate(user.gotp));
      });
    }
  },
  
  'checkpasswd': {
    comment: 'Check a specific user\'s password',
    prm: [ 'pseudo', 'passwd' ],
    proc: (db, pseudo, passwd) => {
      return db.users.findOne({ pseudo }).then(user => {
        const crypto = require('crypto');
        const ec = require('secp256k1');

        // Server-side: GET /api/prelogin(pseudo) => c
        let c = crypto.randomBytes(256 / 8);
        console.log('c: ' + c.toString('hex'));

        // Client-side: generate s = sign(c)
        let key = Buffer.alloc(32);
        crypto.createHash('ripemd160').update(crypto.pbkdf2Sync(passwd, pseudo, 42, 32, 'sha256')).digest().copy(key, 12);
        let s = ec.sign(c, key).signature;
        console.log('s: ' + s.toString('hex'));

        // Server-side: GET /api/login(pseudo, s)
        console.log(ec.verify(c, s, Buffer.from(user.pkey, 'hex')));
      }).catch(() => {
        throw 'Unknown user..';
      });
    }
  }
};

function action(args) {
  let cmd;

  if ((args.length == 0) || ((cmd = cmds[args[0]]) === undefined) || (args.length != cmd.prm.length + 1)) {
    console.log('users.js <cmd> [<param> ..]');
    for (let key in cmds)
      console.log(key + ' ' + cmds[key].prm.join(' ') + ': ' + cmds[key].comment);
    process.exit(1);
  } else {
    require('mongodb').MongoClient.connect('mongodb://localhost:27017', { useNewUrlParser: true }).then(client => {
      args[0] = {
        users: client.db('cerberus').collection('users'),
        g_users: client.db('cerberus').collection('g_users')
      };
      cmd.proc.apply(null, args)
        .then(() => {
          client.close();
          process.exit();
        })
        .catch(err => {
          console.log(err);
          client.close();
          process.exit(2);
        });
    });
  }
}

action(process.argv.slice(2));
