const mocha = require('mocha');
const expect = require('chai').expect;

const $ = require('../lib/test.js');


describe('Start', function() {
  it('should send ready message', function (done) {
    process.send = function(event) {
      expect(event).to.equal('ready');
      done();
    }
    require('../');
  });
});


describe('/auth', function () {
  beforeEach(function () { $.reset() });

  it('should accept with correct token', function () {
    let user = $.addUser("H", "Hydrogen", "1.0079");
    let session = $.addSession(user.pseudo);

    return $.get('/auth', session.token).then(function (res) {
      expect(res.statusCode).to.equal(204);
      expect($.mdb.sessions.deleteMany.called).to.be.true;
      expect($.mdb.sessions.updateOne.calledWith({ _id: session._id })).to.be.true;
    });
  });

  it('should block without token', function () {
    return $.get('/auth').then(function (res) {
      expect(res.statusCode).to.equal(401);
      expect($.mdb.sessions.deleteMany.called).to.be.false;
    });
  });
});


describe('/api/info', function () {
  beforeEach(function () { $.reset() });

  it('should return session user data', function () {
    let user = $.addUser("He", "Helium", "4.0026");
    let session = $.addSession(user.pseudo);

    return $.get('/api/info', session.token).then(function (res) {
      expect(res.statusCode).to.equal(200);
      expect(res.body).to.deep.equal({ name: session.name, pseudo: session.pseudo, token: session.token });
    });
  });

  it('should return {} with invalid session', function () {
    let token = 'Invalid token';

    return $.get('/api/info', token).then(function (res) {
      expect(res.statusCode).to.equal(200);
      expect(res.body).to.deep.equal({});
    });
  });

  it('should return {} without session', function () {
    return $.get('/api/info').then(function (res) {
      expect(res.statusCode).to.equal(200);
      expect(res.body).to.deep.equal({});
    });
  });
});


describe('/api/prelogin', function () {
  beforeEach(function () { $.reset() });

  it('should try to link returned value to user', function () {
    let user = $.addUser("Li", "Lithium", "6.941");

    return $.post('/api/prelogin', { l: user.pseudo }).then(function (res) {
      expect(res.statusCode).to.equal(200);
      expect(res.body).to.have.property('c');
      expect($.mdb.users.updateOne.calledWithExactly({ pseudo: user.pseudo }, { $set: { c: res.body.c } })).to.be.true;
    });
  });

  it('should return 400 if no user specified', function () {
    return $.post('/api/prelogin', {}).then(function (res) {
      expect(res.statusCode).to.equal(400);
    });
  });

  it('should return 400 if invalid (not string) user specified', function () {
    return $.post('/api/prelogin', { l: { evil: 666 } }).then(function (res) {
      expect(res.statusCode).to.equal(400);
    });
  });
});

describe('/api/login', function () {
  beforeEach(function () { $.reset() });

  it('should create new session when logging-in correctly', function () {
    let user = $.addUser("Be", "Beryllium", "9.0122");
    let c = $.genUserC(user.pseudo);
    let r = $.signature(c, user.pseudo);
    let g = $.getUserOTP(user.pseudo);

    return $.post('/api/login', { l: user.pseudo, r: r.toString('hex'), g: g }).then(function (res) {
      expect(res.statusCode).to.equal(200);
      expect($.mdb.users.updateOne.calledWithExactly({ pseudo: user.pseudo }, { $unset: { c: true } })).to.be.true;
      expect($.mdb.sessions.deleteOne.called).to.be.false;
      expect($.mdb.sessions.insertOne.called).to.be.true;
      let args = $.mdb.sessions.insertOne.args[0][0];
      expect(args).to.have.property('name', user.name);
      expect(args).to.have.property('pseudo', user.pseudo);
      expect(args).to.have.property('token', res.body.token);
      expect(args).to.have.property('ip', '::ffff:127.0.0.1');
      expect(args).to.have.property('ua');
      expect(args).to.have.property('lastUsed');
    });
  });

  it('should create new session even with previous totp code', function () {
    let user = $.addUser("B", "Boron", "10.811");
    let c = $.genUserC(user.pseudo);
    let r = $.signature(c, user.pseudo);
    let g = $.getUserOTP(user.pseudo, -30);

    return $.post('/api/login', { l: user.pseudo, r: r.toString('hex'), g: g }).then(function (res) {
      expect(res.statusCode).to.equal(200);
      expect($.mdb.users.updateOne.calledWithExactly({ pseudo: user.pseudo }, { $unset: { c: true } })).to.be.true;
      expect($.mdb.sessions.deleteOne.called).to.be.false;
      expect($.mdb.sessions.insertOne.called).to.be.true;
      let args = $.mdb.sessions.insertOne.args[0][0];
      expect(args).to.have.property('name', user.name);
      expect(args).to.have.property('pseudo', user.pseudo);
      expect(args).to.have.property('token', res.body.token);
      expect(args).to.have.property('ip', '::ffff:127.0.0.1');
      expect(args).to.have.property('ua');
      expect(args).to.have.property('lastUsed');
    });
  });

  it('should refuse with an older totp code', function () {
    let user = $.addUser("C", "Carbon", "12.0107");
    let c = $.genUserC(user.pseudo);
    let r = $.signature(c, user.pseudo);
    let g = $.getUserOTP(user.pseudo, -120);

    return $.post('/api/login', { l: user.pseudo, r: r.toString('hex'), g: g }).then(function (res) {
      expect(res.statusCode).to.equal(401);
      expect($.mdb.users.updateOne.calledWithExactly({ pseudo: user.pseudo }, { $unset: { c: true } })).to.be.true;
      expect($.mdb.sessions.deleteOne.called).to.be.false;
      expect($.mdb.sessions.insertOne.called).to.be.false;
    });
  });

  it('should refuse with an invalid password', function () {
    let user = $.addUser("N", "Nitrogen", "14.0067");
    let c = $.genUserC(user.pseudo);
    let r = $.signature(c, user.pseudo, "invalid_pass");
    let g = $.getUserOTP(user.pseudo);

    return $.post('/api/login', { l: user.pseudo, r: r.toString('hex'), g: g }).then(function (res) {
      expect(res.statusCode).to.equal(401);
      expect($.mdb.users.updateOne.calledWithExactly({ pseudo: user.pseudo }, { $unset: { c: true } })).to.be.true;
      expect($.mdb.sessions.deleteOne.called).to.be.false;
      expect($.mdb.sessions.insertOne.called).to.be.false;
    });
  });

  it('should delete current session if any', function () {
    let user = $.addUser("O", "Oxygen", "15.9994");
    let c = $.genUserC(user.pseudo);
    let r = $.signature(c, user.pseudo);
    let g = $.getUserOTP(user.pseudo);
    let session = $.addSession(user.pseudo);

    return $.post('/api/login', { l: user.pseudo, r: r.toString('hex'), g: g }, session.token).then(function (res) {
      expect(res.statusCode).to.equal(200);
      expect($.mdb.sessions.deleteOne.called).to.be.true;
    });
  });
});

describe('/api/logout', function () {
  beforeEach(function () { $.reset() });

  it('should try to logout', function () {
    let user = $.addUser("F", "Fluorine", "18.9984");
    let session = $.addSession(user.pseudo);

    return $.get('/api/logout', session.token).then(function (res) {
      expect(res.statusCode).to.equal(204);
      expect($.mdb.sessions.deleteOne.called).to.be.true;
      expect($.mdb.sessions.deleteOne.args).to.deep.equal([ [ { _id: session._id } ] ]);
    });
  });

  it('should silently ignore invalid session', function () {
    return $.get('/api/logout').then(function (res) {
      expect(res.statusCode).to.equal(204);
    });
  });
});

describe('/api/geninfo', function () {
  beforeEach(function () { $.reset() });

  it('should return new user information', function () {
    let guser = $.addGUser("Ne", "Neon");

    return $.post('/api/geninfo', { gid: guser.gid }).then(function (res) {
      expect(res.statusCode).to.equal(200);
      expect(res.body.pseudo).to.equal(guser.pseudo);
      expect(res.body.qrcode).to.equal("otpauth://totp/cerberus:" + guser.pseudo + "?secret=" + guser.gotp + "&issuer=cerberus");
    });
  });

  it('should return 401 if new user not found', function () {
    return $.post('/api/geninfo', { gid: "Invalid_gid" }).then(function (res) {
      expect(res.statusCode).to.equal(401);
    });
  });
});

describe('/api/generate', function () {
  beforeEach(function () { $.reset() });

  it('should finish user registration', function () {
    let guser = $.addGUser("Na", "Sodium", "22.9897");
    let pkey = $.getGUserPKey(guser.pseudo);
    let g = $.getUserOTP(guser.pseudo);

    return $.post('/api/generate', { gid: guser.gid, g: g, k: pkey }).then(function (res) {
      expect(res.statusCode).to.equal(200);
      expect(res.body.name).to.equal(guser.name);
      expect(res.body.pseudo).to.equal(guser.pseudo);
      expect(res.body).to.have.property('token');
      expect($.mdb.sessions.deleteOne.called).to.be.false;
      expect($.mdb.g_users.deleteOne.args).to.deep.equal([ [ { gid: guser.gid } ] ]);
      expect($.mdb.users.insertOne.called).to.be.true;
      expect($.mdb.users.insertOne.args[0][0]).to.deep.equal({
        name: guser.name, pseudo: guser.pseudo, pkey: pkey, gotp: guser.gotp
      })
      let args = $.mdb.sessions.insertOne.args[0][0];
      expect(args).to.have.property('name', guser.name);
      expect(args).to.have.property('pseudo', guser.pseudo);
      expect(args).to.have.property('token', res.body.token);
      expect(args).to.have.property('ip', '::ffff:127.0.0.1');
      expect(args).to.have.property('ua');
      expect(args).to.have.property('lastUsed');
    });
  });

  it('should return 400 if a session already exists', function () {
    let guser = $.addGUser("Mg", "Magnesium", "24.305");
    let pkey = $.getGUserPKey(guser.pseudo);
    let g = $.getUserOTP(guser.pseudo);
    let other_user = $.addUser("F", "Fluorine", "18.9984");
    let other_session = $.addSession(other_user.pseudo);

    return $.post('/api/generate', { gid: guser.gid, g: g, k: pkey }, other_session.token).then(function (res) {
      expect(res.statusCode).to.equal(400);
    });
  });

  it('should return 401 if user is unknown', function () {
    let guser = $.addGUser("Al", "Aluminum", "26.9815");
    let pkey = $.getGUserPKey(guser.pseudo);
    let g = $.getUserOTP(guser.pseudo);

    return $.post('/api/generate', { gid: 'Invalid_gid', g: g, k: pkey }).then(function (res) {
      expect(res.statusCode).to.equal(401);
    });
  });

  it('should return 403 if totp code is old', function () {
    let guser = $.addGUser("Si", "Silicon", "28.0855");
    let pkey = $.getGUserPKey(guser.pseudo);
    let g = $.getUserOTP(guser.pseudo, -120);

    return $.post('/api/generate', { gid: guser.gid, g: g, k: pkey }).then(function (res) {
      expect(res.statusCode).to.equal(403);
    });
  });
});

describe('/api/list', function () {
  beforeEach(function () { $.reset() });

  it('should return current user\'s sessions', function () {
    let user = $.addUser("P", "Phosphorus", "30.9738");
    /* let session1 = */ $.addSession(user.pseudo);
    let session2 = $.addSession(user.pseudo);
    /* let session3 = */ $.addSession(user.pseudo);

    return $.get('/api/list', session2.token).then(function (res) {
      expect(res.statusCode).to.equal(200);
      expect(res.body).to.be.an('array').that.have.length(3);
      let c = res.body.find(function (el) { return el.current === true });
      expect(c).to.not.be.undefined;
      expect(session2._id.equals(c._id)).to.be.true;
      for (let s of res.body)
        expect(s.pseudo).to.equal(user.pseudo);
    });
  });

  it('should return 401 for invalid session', function () {
    let token = 'Invalid token';

    return $.get('/api/list', token).then(function (res) {
      expect(res.statusCode).to.equal(401);
    });
  });
});

describe('/api/remove', function () {
  beforeEach(function () { $.reset() });

  it('should remove specified session', function () {
    let user = $.addUser("S", "Sulfur", "32.065");
    let session = $.addSession(user.pseudo);

    return $.post('/api/remove', { sid: session._id.toString() }, session.token).then(function (res) {
      expect(res.statusCode).to.equal(204);
      expect($.mdb.sessions.deleteOne.called).to.be.true;
      expect($.mdb.sessions.deleteOne.args).to.deep.equal([ [ { _id: session._id.toString(), pseudo: user.pseudo } ] ]);
    });
  });

  it('should return 401 if current session is invalid', function () {
    return $.post('/api/remove', { sid: "Invalid_sid" }).then(function (res) {
      expect(res.statusCode).to.equal(401);
      expect($.mdb.sessions.deleteOne.called).to.be.false;
    });
  });
});

describe('/api/flush', function () {
  beforeEach(function () { $.reset() });

  it('should remove all but current sessions', function () {
    let user = $.addUser("Cl", "Chlorine", "35.453");
    /* let session1 = */ $.addSession(user.pseudo);
    let session2 = $.addSession(user.pseudo);
    /* let session3 = */ $.addSession(user.pseudo);

    return $.get('/api/flush', session2.token).then(function (res) {
      expect(res.statusCode).to.equal(204);
      expect($.mdb.sessions.deleteMany.called).to.be.true;
      expect($.mdb.sessions.deleteMany.args).to.deep.equal([ [ { pseudo: user.pseudo, _id: { $ne: session2._id } } ] ]);
    });
  });

  it('should return 401 if current session is invalid', function () {
    return $.post('/api/remove', { sid: "Invalid_sid" }).then(function (res) {
      expect(res.statusCode).to.equal(401);
      expect($.mdb.sessions.deleteOne.called).to.be.false;
    });
  });
});
