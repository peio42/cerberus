/* global context, describe, beforeEach, it */

const sinon = require('sinon');
const { expect } = require('chai');
const { readFileSync } = require('fs');
const vm = require('vm');

const $ = require('./helper.js');


context('Tools', () => {
  describe('users.js', () => {
    var sb = {
      process: { exit: sinon.stub(), argv: [ 'node', 'users.js' ] },
      console: { log: sinon.stub() },
      require,
      Buffer
    };

    beforeEach(() => {
      $.reset();
      sb.process.exit.reset();
      sb.console.log.reset();
    });

    describe('loading', () => {
      it('should give help without argument', done => {
        sb.process.exit.callsFake(ec => {
          expect(sb.console.log.callCount).to.equal(1 /* usage */ + 3 /* commands */);
          expect(ec).to.equal(1);
          done();
        });

        let code = readFileSync('tools/users.js').toString().split('\n');
        code.splice(0, 1);
        code = code.join('\n');
        vm.createContext(sb);
        vm.runInContext(code, sb);
      });
    });

    describe('list', () => {
      it('should list users', done => {
        let u1 = $.addUser('H', 'Hydrogen', '1.0079');
        let u2 = $.addUser('He', 'Helium', '4.0026');

        sb.process.exit.callsFake(() => {
          let items = sb.console.log.args[0][0];
          expect(items).to.have.lengthOf(2);
          expect(items[0].name).to.equal(u1.name);
          expect(items[1].name).to.equal(u2.name);

          done();
        });

        sb.action([ 'list' ]);
      });
    });

    describe('otpcode', () => {
      it('should send correct OTP code', done => {
        let u1 = $.addUser('H', 'Hydrogen', '1.0079');
        $.addUser('He', 'Helium', '4.0026');

        sb.process.exit.callsFake(() => {
          expect(sb.console.log.args[0][0]).to.equal($.getUserOTP(u1.pseudo, 0));

          done();
        });

        sb.action([ 'otpcode', u1.pseudo ]);
      });
    });

    describe('checkpasswd', () => {
      it('should accept good password (10x)', () => {
        let u1 = $.addUser('H', 'Hydrogen', '1.0079');
        let p = Promise.resolve();

        for (let i = 0; i < 10; i++) {
          p = p.then(() => {
            sb.action([ 'checkpasswd', u1.pseudo, $.users[u1.pseudo].password ]);
            return new Promise((resolve, _reject) => {
              sb.process.exit.callsFake(() => {
                expect(sb.console.log.callCount).to.equal(3);
                expect(sb.console.log.args[2][0]).to.be.true;
                resolve();
                
                sb.console.log.resetHistory();
              });
            });
          });
        }

        return p;
      });

      it('should refuse wrong password (10x)', () => {
        let u1 = $.addUser('H', 'Hydrogen', '1.0079');
        let p = Promise.resolve();

        for (let i = 0; i < 10; i++) {
          p = p.then(() => {
            sb.action([ 'checkpasswd', u1.pseudo, $.users[u1.pseudo].password + 'x' ]);
            return new Promise((resolve, _reject) => {
              sb.process.exit.callsFake(() => {
                expect(sb.console.log.callCount).to.equal(3); // "c: .." / "s: .." / "true|false"
                expect(sb.console.log.args[2][0]).to.be.false;
                resolve();
                
                sb.console.log.resetHistory();
              });
            });
          });
        }

        return p;
      });
    });
  });

  describe('sessions.js', () => {
    var sb = {
      process: { exit: sinon.stub(), argv: [ 'node', 'sessions.js' ] },
      console: { log: sinon.stub() },
      require,
      Buffer
    };

    beforeEach(() => {
      $.reset();
      sb.process.exit.reset();
      sb.console.log.reset();
    });

    describe('loading', () => {
      it('should give help without argument', done => {
        sb.process.exit.callsFake(ec => {
          expect(sb.console.log.callCount).to.equal(1 /* usage */ + 3 /* commands */);
          expect(ec).to.equal(1);
          done();
        });

        let code = readFileSync('tools/sessions.js').toString().split('\n');
        code.splice(0, 1);
        code = code.join('\n');
        vm.createContext(sb);
        vm.runInContext(code, sb);
      });
    });

    describe('list', () => {
      it('should list sessions', done => {
        let u1 = $.addUser('H', 'Hydrogen', '1.0079');
        let u2 = $.addUser('He', 'Helium', '4.0026');
        let s1 = $.addSession(u1.pseudo);
        let s2 = $.addSession(u1.pseudo);
        let s3 = $.addSession(u2.pseudo);

        sb.process.exit.callsFake(() => {
          let items = sb.console.log.args[0][0];
          expect(items).to.have.lengthOf(3);
          expect(items[0].name).to.equal(s1.name);
          expect(items[1].name).to.equal(s2.name);
          expect(items[2].name).to.equal(s3.name);

          done();
        });

        sb.action([ 'list' ]);
      });
    });

    describe('update', () => {
      it('should update a session', done => {
        let user = $.addUser('H', 'Hydrogen', '1.0079');
        let session = $.addSession(user.pseudo);

        sb.process.exit.callsFake(() => {
          expect($.mdb.sessions.updateOne.calledWith({ token: session.token })).to.be.true;
          done();
        });

        sb.action([ 'update', session.token ]);
      });
    });

    describe('delete', () => {
      it('should delete a session', done => {
        let user = $.addUser('H', 'Hydrogen', '1.0079');
        let session = $.addSession(user.pseudo);

        sb.process.exit.callsFake(() => {
          expect($.mdb.sessions.deleteOne.calledWith({ token: session.token })).to.be.true;

          done();
        });

        sb.action([ 'delete', session.token ]);
      });
    });
  });
});
