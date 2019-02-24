/* global describe, beforeEach, it */

const expect = require('chai').expect;

const $ = require('./helper.js');


describe('Start', () => {
  it('should send ready message', done => {
    process.send = event => {
      expect(event).to.equal('ready');
      done();
    };
    require('../');
  });
});


describe('/auth', () => {
  beforeEach($.reset);

  it('should accept with correct token', async () => {
    let user = $.addUser('H', 'Hydrogen', '1.0079');
    let session = $.addSession(user.pseudo);

    const res = await $.get('/auth', session.token);
    expect(res.statusCode).to.equal(204);
    expect($.mdb.sessions.deleteMany.called).to.be.true;
    expect($.mdb.sessions.updateOne.calledWith({ _id: session._id })).to.be.true;
  });

  it('should block without token', async () => {
    const res = await $.get('/auth');
    expect(res.statusCode).to.equal(401);
    expect($.mdb.sessions.deleteMany.called).to.be.false;
  });
});


describe('/api/info', () => {
  beforeEach($.reset);

  it('should return session user data', async () => {
    let user = $.addUser('He', 'Helium', '4.0026');
    let session = $.addSession(user.pseudo);

    const res = await $.get('/api/info', session.token);
    expect(res.statusCode).to.equal(200);
    expect(res.body).to.deep.equal({ name: session.name, pseudo: session.pseudo, token: session.token });
  });

  it('should return {} with invalid session', async () => {
    let token = 'Invalid token';

    const res = await $.get('/api/info', token);
    expect(res.statusCode).to.equal(200);
    expect(res.body).to.deep.equal({});
  });

  it('should return {} without session', async () => {
    const res = await $.get('/api/info');
    expect(res.statusCode).to.equal(200);
    expect(res.body).to.deep.equal({});
  });
});


describe('/api/prelogin', () => {
  beforeEach($.reset);

  it('should try to link returned value to user', async () => {
    let user = $.addUser('Li', 'Lithium', '6.941');

    const res = await $.post('/api/prelogin', { l: user.pseudo });
    expect(res.statusCode).to.equal(200);
    expect(res.body).to.have.property('c');
    expect($.mdb.users.updateOne.calledWithExactly({ pseudo: user.pseudo }, { $set: { c: res.body.c } })).to.be.true;
  });

  it('should return 400 if no user specified', async () => {
    const res = await $.post('/api/prelogin', {});
    expect(res.statusCode).to.equal(400);
  });

  it('should return 400 if invalid (not string) user specified', async () => {
    const res = await $.post('/api/prelogin', { l: { evil: 666 } });
    expect(res.statusCode).to.equal(400);
  });
});

describe('/api/login', () => {
  beforeEach($.reset);

  it('should create new session when logging-in correctly', async () => {
    let user = $.addUser('Be', 'Beryllium', '9.0122');
    let c = $.genUserC(user.pseudo);
    let r = $.signature(c, user.pseudo);
    let g = $.getUserOTP(user.pseudo);

    const res = await $.post('/api/login', { l: user.pseudo, r: r.toString('hex'), g: g });
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

  it('should create new session even with previous totp code', async () => {
    let user = $.addUser('B', 'Boron', '10.811');
    let c = $.genUserC(user.pseudo);
    let r = $.signature(c, user.pseudo);
    let g = $.getUserOTP(user.pseudo, -30);

    const res = await $.post('/api/login', { l: user.pseudo, r: r.toString('hex'), g: g });
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

  it('should refuse with an older totp code', async () => {
    let user = $.addUser('C', 'Carbon', '12.0107');
    let c = $.genUserC(user.pseudo);
    let r = $.signature(c, user.pseudo);
    let g = $.getUserOTP(user.pseudo, -120);

    const res = await $.post('/api/login', { l: user.pseudo, r: r.toString('hex'), g: g });
    expect(res.statusCode).to.equal(401);
    expect($.mdb.users.updateOne.calledWithExactly({ pseudo: user.pseudo }, { $unset: { c: true } })).to.be.true;
    expect($.mdb.sessions.deleteOne.called).to.be.false;
    expect($.mdb.sessions.insertOne.called).to.be.false;
  });

  it('should refuse with an invalid password', async () => {
    let user = $.addUser('N', 'Nitrogen', '14.0067');
    let c = $.genUserC(user.pseudo);
    let r = $.signature(c, user.pseudo, 'invalid_pass');
    let g = $.getUserOTP(user.pseudo);

    const res = await $.post('/api/login', { l: user.pseudo, r: r.toString('hex'), g: g });
    expect(res.statusCode).to.equal(401);
    expect($.mdb.users.updateOne.calledWithExactly({ pseudo: user.pseudo }, { $unset: { c: true } })).to.be.true;
    expect($.mdb.sessions.deleteOne.called).to.be.false;
    expect($.mdb.sessions.insertOne.called).to.be.false;
  });

  it('should delete current session if any', async () => {
    let user = $.addUser('O', 'Oxygen', '15.9994');
    let c = $.genUserC(user.pseudo);
    let r = $.signature(c, user.pseudo);
    let g = $.getUserOTP(user.pseudo);
    let session = $.addSession(user.pseudo);

    const res = await $.post('/api/login', { l: user.pseudo, r: r.toString('hex'), g: g }, session.token);
    expect(res.statusCode).to.equal(200);
    expect($.mdb.sessions.deleteOne.called).to.be.true;
  });
});

describe('/api/logout', function () {
  beforeEach($.reset);

  it('should try to logout', async () => {
    let user = $.addUser('F', 'Fluorine', '18.9984');
    let session = $.addSession(user.pseudo);

    const res = await $.get('/api/logout', session.token);
    expect(res.statusCode).to.equal(204);
    expect($.mdb.sessions.deleteOne.called).to.be.true;
    expect($.mdb.sessions.deleteOne.args).to.deep.equal([[{ _id: session._id }]]);
  });

  it('should silently ignore invalid session', async () => {
    const res = await $.get('/api/logout');
    expect(res.statusCode).to.equal(204);
  });
});

describe('/api/geninfo', () => {
  beforeEach($.reset);

  it('should return new user information', async () => {
    let guser = $.addGUser('Ne', 'Neon');

    const res = await $.post('/api/geninfo', { gid: guser.gid });
    expect(res.statusCode).to.equal(200);
    expect(res.body.pseudo).to.equal(guser.pseudo);
    expect(res.body.qrcode).to.equal('otpauth://totp/cerberus:' + guser.pseudo + '?secret=' + guser.gotp + '&issuer=cerberus');
  });

  it('should return 401 if new user not found', async () => {
    const res = await $.post('/api/geninfo', { gid: 'Invalid_gid' });
    expect(res.statusCode).to.equal(401);
  });
});

describe('/api/generate', () => {
  beforeEach($.reset);

  it('should finish user registration', async () => {
    let guser = $.addGUser('Na', 'Sodium', '22.9897');
    let pkey = $.getGUserPKey(guser.pseudo);
    let g = $.getUserOTP(guser.pseudo);

    const res = await $.post('/api/generate', { gid: guser.gid, g: g, k: pkey });
    expect(res.statusCode).to.equal(200);
    expect(res.body.name).to.equal(guser.name);
    expect(res.body.pseudo).to.equal(guser.pseudo);
    expect(res.body).to.have.property('token');
    expect($.mdb.sessions.deleteOne.called).to.be.false;
    expect($.mdb.g_users.deleteOne.args).to.deep.equal([[{ gid: guser.gid }]]);
    expect($.mdb.users.insertOne.called).to.be.true;
    expect($.mdb.users.insertOne.args[0][0]).to.deep.equal({
      name: guser.name, pseudo: guser.pseudo, pkey: pkey, gotp: guser.gotp
    });
    let args = $.mdb.sessions.insertOne.args[0][0];
    expect(args).to.have.property('name', guser.name);
    expect(args).to.have.property('pseudo', guser.pseudo);
    expect(args).to.have.property('token', res.body.token);
    expect(args).to.have.property('ip', '::ffff:127.0.0.1');
    expect(args).to.have.property('ua');
    expect(args).to.have.property('lastUsed');
  });

  it('should return 400 if a session already exists', async () => {
    let guser = $.addGUser('Mg', 'Magnesium', '24.305');
    let pkey = $.getGUserPKey(guser.pseudo);
    let g = $.getUserOTP(guser.pseudo);
    let other_user = $.addUser('F', 'Fluorine', '18.9984');
    let other_session = $.addSession(other_user.pseudo);

    const res = await $.post('/api/generate', { gid: guser.gid, g: g, k: pkey }, other_session.token);
    expect(res.statusCode).to.equal(400);
  });

  it('should return 401 if user is unknown', async () => {
    let guser = $.addGUser('Al', 'Aluminum', '26.9815');
    let pkey = $.getGUserPKey(guser.pseudo);
    let g = $.getUserOTP(guser.pseudo);

    const res = await $.post('/api/generate', { gid: 'Invalid_gid', g: g, k: pkey });
    expect(res.statusCode).to.equal(401);
  });

  it('should return 403 if totp code is old', async () => {
    let guser = $.addGUser('Si', 'Silicon', '28.0855');
    let pkey = $.getGUserPKey(guser.pseudo);
    let g = $.getUserOTP(guser.pseudo, -120);

    const res = await $.post('/api/generate', { gid: guser.gid, g: g, k: pkey });
    expect(res.statusCode).to.equal(403);
  });
});

describe('/api/list', function () {
  beforeEach($.reset);

  it('should return current user\'s sessions', async () => {
    let user = $.addUser('P', 'Phosphorus', '30.9738');
    /* let session1 = */ $.addSession(user.pseudo);
    let session2 = $.addSession(user.pseudo);
    /* let session3 = */ $.addSession(user.pseudo);

    const res = await $.get('/api/list', session2.token);
    expect(res.statusCode).to.equal(200);
    expect(res.body).to.be.an('array').that.have.length(3);
    let c = res.body.find(el => el.current === true);
    expect(c).to.not.be.undefined;
    expect(session2._id.equals(c._id)).to.be.true;
    for (let s of res.body)
      expect(s.pseudo).to.equal(user.pseudo);
  });

  it('should return 401 for invalid session', async () => {
    let token = 'Invalid token';

    const res = await $.get('/api/list', token);
    expect(res.statusCode).to.equal(401);
  });
});

describe('/api/remove', () => {
  beforeEach($.reset);

  it('should remove specified session', async () => {
    let user = $.addUser('S', 'Sulfur', '32.065');
    let session = $.addSession(user.pseudo);

    const res = await $.post('/api/remove', { sid: session._id.toString() }, session.token);
    expect(res.statusCode).to.equal(204);
    expect($.mdb.sessions.deleteOne.called).to.be.true;
    expect($.mdb.sessions.deleteOne.args).to.deep.equal([[{ _id: session._id.toString(), pseudo: user.pseudo }]]);
  });

  it('should return 401 if current session is invalid', async () => {
    const res = await $.post('/api/remove', { sid: 'Invalid_sid' });
    expect(res.statusCode).to.equal(401);
    expect($.mdb.sessions.deleteOne.called).to.be.false;
  });
});

describe('/api/flush', () => {
  beforeEach($.reset);

  it('should remove all but current sessions', async () => {
    let user = $.addUser('Cl', 'Chlorine', '35.453');
    /* let _session1 = */ $.addSession(user.pseudo);
    let session2 = $.addSession(user.pseudo);
    /* let session3 = */ $.addSession(user.pseudo);

    const res = await $.get('/api/flush', session2.token);
    expect(res.statusCode).to.equal(204);
    expect($.mdb.sessions.deleteMany.called).to.be.true;
    expect($.mdb.sessions.deleteMany.args).to.deep.equal([[{ pseudo: user.pseudo, _id: { $ne: session2._id } }]]);
  });

  it('should return 401 if current session is invalid', async () => {
    const res = await $.post('/api/remove', { sid: 'Invalid_sid' });
    expect(res.statusCode).to.equal(401);
    expect($.mdb.sessions.deleteMany.called).to.be.false;
  });
});
