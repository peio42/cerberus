#!/usr/bin/node

const args = process.argv.slice(2);

const cmds = {
  'list': {
    comment: 'List current sessions',
    prm: [ ],
    proc: db => {
      return db.find().toArray().then(items => {
        console.log(items);
      });
    }
  },

  'update': {
    comment: 'Update lastUsed field of a specific session',
    prm: [ 'token' ],
    proc: (db, token) => {
      return db.updateOne({ token: token }, { $set: { lastUsed: Date.now() } });
    }
  },

  'delete': {
    comment: 'Delete a session',
    prm: [ 'id' ],
    proc: (db, id) => {
      return db.deleteOne({ _id: new require('mongodb').ObjectID(id) });
    }
  }
};


var cmd;
if ((args.length == 0) || ((cmd = cmds[args[0]]) === undefined) || (args.length != cmd.prm.length + 1)) {
  console.log("sessions.js <cmd> [<param> ..]");
  for (let key in cmds)
    console.log(key + ": " + cmds[key].comment);
  process.exit(1);
} else {
  require('mongodb').MongoClient.connect('mongodb://localhost:27017', { useNewUrlParser: true }).then(client => {
    args[0] = client.db('cerberus').collection('sessions');
    cmd.proc.apply(null, args)
      .catch(err => { console.log(err) })
      .finally(() => {
        client.close();
        process.exit();
      });
  });
}
