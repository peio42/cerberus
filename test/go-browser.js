/* global describe, context, before, after, beforeEach, afterEach, it, dom, window, angular */

const { expect } = require('chai');
const { randomBytes } = require('crypto');
const { JSDOM } = require('jsdom');
const crypto = require('crypto');
const { publicKeyCreate, publicKeyConvert, verify, signatureNormalize } = require('secp256k1');
const randomstring = require('randomstring');


context('Browser', () => {
  var ngModule, ngInject;

  before(function (done) {
    this.timeout(10000);

    JSDOM.fromFile('test/browser.html', { runScripts: 'dangerously', resources: 'usable' }).then(dom => {
      dom.reconfigure({ url: 'http://example.org' });
      global.dom = dom;
      global.window = dom.window;
      window.crypto = { getRandomValues: buffer => require('crypto').randomBytes(buffer.length) };
      window.mocha = true;
      window.beforeEach = beforeEach;
      window.afterEach = afterEach;

      (function checkReady() {
        if (! (window.angular && window.sjcl && window.UAParser))
          return setTimeout(checkReady, 100);

        console.log('Modules ready.');
        global.angular = window.angular;
        global.sjcl = window.sjcl;
        global.UAParser = window.UAParser;

        require('angular-mocks');
        ngModule = angular.mock.module;
        ngInject = angular.mock.inject;

        done();
      })();
    });
  });

  after(function () {
    delete global.dom;
    delete global.window;
    delete global.angular;
    delete global.sjcl;
    delete global.UAParser;
  });


  describe('Loading', () => {
    var $httpBackend;

    it('should load "cerberus.js" script', () => {
      require('../root/cerberus.js');

      ngModule('cerberus');
      ngInject(_$httpBackend_ => {
        $httpBackend = _$httpBackend_;

        $httpBackend.expectGET('home.inc.html').respond(201, '');
        $httpBackend.flush();

        $httpBackend.verifyNoOutstandingExpectation();
        $httpBackend.verifyNoOutstandingRequest();
      });
    });
  });


  describe('"auth" service', () => {
    var auth, $httpBackend;
    var localStorageStack = [ ];

    beforeEach(() => {
      window.localStorage.setItem('ls.authInfo', JSON.stringify(localStorageStack.shift()));

      ngModule('cerberus');
      ngInject((_auth_, _$httpBackend_) => {
        auth = _auth_;
        $httpBackend = _$httpBackend_;
      });

      $httpBackend.whenGET('home.inc.html').respond(201, '');
    });

    afterEach(() => {
      $httpBackend.verifyNoOutstandingExpectation();
      $httpBackend.verifyNoOutstandingRequest();

      window.localStorage.removeItem('ls.authInfo');
      window.document.cookie = 'cerberus=;expires=Thu, 01 Jan 1970 00:00:01 GMT';
    });

    describe('localStorage', () => {
      localStorageStack.push({ name: 'name', pseudo: 'pseudo', token: 'token' });
      it('should take authInfo from localStorage if present', () => {
        expect(auth.name()).to.equal('name');
        expect(auth.pseudo()).to.equal('pseudo');
        expect(auth.isLoggedIn()).to.be.true;
        expect(window.document.cookie).to.equal('cerberus=token');

        $httpBackend.flush();
      });

      localStorageStack.push(null);
      it('should start with empty authInfo if not', () => {
        expect(auth.isLoggedIn()).to.be.false;
        expect(window.document.cookie).to.equal('');

        $httpBackend.flush();
      });
    });

    describe('auth.login', () => {
      localStorageStack.push(null);
      it('should handle angry /api/prelogin', done => {
        $httpBackend.expectPOST('/api/prelogin').respond(401, '');

        auth.login('pseudo', 'password', '000000').then(null, done);

        $httpBackend.flush();
      });

      localStorageStack.push(null);
      it('should handle angry /api/login', done => {
        let c = randomBytes(32).toString('hex');

        $httpBackend.expectPOST('/api/prelogin').respond(200, JSON.stringify({ c }));
        $httpBackend.expectPOST('/api/login').respond(401, '');

        auth.login('pseudo', 'password', '000000').then(null, done);

        $httpBackend.flush();
      });

      localStorageStack.push(null);
      it('should handle positive login (10x)', () => {
        for (let i = 0; i < 10; i++) {
          let c = randomBytes(32).toString('hex');
          let name = randomstring.generate(12);
          let pseudo = randomstring.generate(8);
          let password = randomstring.generate(32);
          let otpcode = randomstring.generate({ length: 6, charset: 'numeric' });
          let token = randomBytes(32).toString('hex');
          let authInfo = { name, pseudo, token };

          $httpBackend.expectPOST('/api/prelogin').respond(200, { c });
          $httpBackend.expectPOST('/api/login').respond((_method, _url, data, _headers, _params) => {
            let priv = Buffer.alloc(32);
            crypto.createHash('ripemd160').update(crypto.pbkdf2Sync(password, pseudo, 42, 32, 'sha256')).digest().copy(priv, 12);
            let pkey = publicKeyCreate(priv);

            data = JSON.parse(data);
            expect(data.l).to.equal(pseudo);
            expect(verify(Buffer.from(c, 'hex'), signatureNormalize(Buffer.from(data.r, 'hex')), pkey)).to.be.true;
            expect(data.g).to.equal(otpcode);
            return [ 200, authInfo ];
          });

          auth.login(pseudo, password, otpcode).then(() => {
            expect(auth.isLoggedIn()).to.be.true;
            expect(JSON.parse(window.localStorage.getItem('ls.authInfo'))).to.deep.equal(authInfo);
            expect(window.document.cookie).to.equal('cerberus=' + authInfo.token);
          });

          $httpBackend.flush();
          expect(window.document.cookie).to.equal('cerberus=' + token);
        }
      });
    });

    describe('auth.logout', () => {
      localStorageStack.push({ name: 'name', pseudo: 'pseudo', token: 'token' });
      it('should handle angry /api/logout', done => {
        $httpBackend.expectGET('/api/logout').respond(401, '');

        auth.logout().then(null, () => {
          expect(auth.isLoggedIn()).to.be.true;
          expect(window.document.cookie).to.equal('cerberus=token');
          done();
        });

        $httpBackend.flush();
      });

      localStorageStack.push({ name: 'name', pseudo: 'pseudo', token: 'token' });
      it('should handle positive logout', done => {
        $httpBackend.expectGET('/api/logout').respond(201, '');

        auth.logout().then(() => {
          expect(auth.isLoggedIn()).to.be.false;
          expect(window.document.cookie).to.equal('');
          done();
        });

        $httpBackend.flush();
      });
    });

    describe('auth.generate', () => {
      localStorageStack.push(null);
      it('should handle angry /api/generate', done => {
        $httpBackend.expectPOST('/api/generate').respond(401, '');

        auth.generate('gid', 'pseudo', 'passwd', '000000').then(null, done);

        $httpBackend.flush();
      });

      localStorageStack.push(null);
      it('should correctly (re-)generate user credentials (10x)', () => {
        for (let i = 0; i < 10; i++) {
          let gid = randomBytes(32).toString('hex');
          let token = randomBytes(32).toString('hex');
          let pseudo = randomstring.generate(8);
          let name = randomstring.generate(12);
          let password = randomstring.generate(32);
          let otpcode = randomstring.generate({ length: 6, charset: 'numeric' });

          $httpBackend.expectPOST('/api/generate').respond((_method, _url, data, _headers, _params) => {
            let priv = Buffer.alloc(32);
            crypto.createHash('ripemd160').update(crypto.pbkdf2Sync(password, pseudo, 42, 32, 'sha256')).digest().copy(priv, 12);
            let pkey = publicKeyCreate(priv);

            data = JSON.parse(data);
            expect(data.gid).to.equal(gid);
            expect(data.k).to.equal(publicKeyConvert(pkey, false).toString('hex'));
            expect(data.g).to.equal(otpcode);

            return [ 200, JSON.stringify({ name, pseudo, token }) ];
          });

          auth.generate(gid, pseudo, password, otpcode);

          $httpBackend.flush();
          expect(auth.isLoggedIn());
          expect(auth.pseudo()).to.equal(pseudo);
          expect(auth.name()).to.equal(name);
          expect(window.document.cookie).to.equal('cerberus=' + token);
        }

      });
    });
  });

  describe('WidgetController', () => {
    var $httpBackend, $controller, $rootScope;
    var localStorageStack = [ ];

    beforeEach(() => {
      window.localStorage.setItem('ls.authInfo', JSON.stringify(localStorageStack.shift()));

      ngModule('cerberus');
      ngInject(($location, _$httpBackend_, _$controller_, _$rootScope_) => {
        $httpBackend = _$httpBackend_;
        $controller = _$controller_;
        $rootScope = _$rootScope_;

        $location.path('/');
        $httpBackend.expectGET('home.inc.html').respond(201, '');
        $rootScope.$digest();
      });
    });

    afterEach(() => {
      $httpBackend.verifyNoOutstandingExpectation();
      $httpBackend.verifyNoOutstandingRequest();

      window.localStorage.removeItem('ls.authInfo');
      window.document.cookie = 'cerberus=;expires=Thu, 01 Jan 1970 00:00:01 GMT';
    });

    describe('$scope.logout', () => {
      localStorageStack.push({ name: 'name', pseudo: 'pseudo', token: 'token' });
      it('should handle angry /api/logout', done => {
        let $scope = $rootScope.$new();
        $controller('WidgetController', { $scope: $scope });

        $httpBackend.expectGET('/api/logout').respond(401, '');

        $scope.logout().then(null, done);

        $httpBackend.flush();
      });

      localStorageStack.push({ name: 'name', pseudo: 'pseudo', token: 'token' });
      it('should logout', done => {
        let $scope = $rootScope.$new();
        $controller('WidgetController', { $scope: $scope });

        $httpBackend.expectGET('/api/logout').respond(201, '');
        $httpBackend.expectGET('login.inc.html').respond(201, '');

        $scope.logout().then(done);

        $httpBackend.flush();
      });
    });
  });

  describe('HomeController', () => {
    var $httpBackend, $controller, $rootScope;
    var localStorageStack = [ ];

    beforeEach(() => {
      window.localStorage.setItem('ls.authInfo', JSON.stringify(localStorageStack.shift()));

      ngModule('cerberus');
      ngInject(($location, _$httpBackend_, _$controller_, _$rootScope_) => {
        $httpBackend = _$httpBackend_;
        $controller = _$controller_;
        $rootScope = _$rootScope_;

        $location.path('/');
        $httpBackend.expectGET('home.inc.html').respond(201, '');
        $rootScope.$digest();
      });
    });

    afterEach(() => {
      $httpBackend.verifyNoOutstandingExpectation();
      $httpBackend.verifyNoOutstandingRequest();

      window.localStorage.removeItem('ls.authInfo');
      window.document.cookie = 'cerberus=;expires=Thu, 01 Jan 1970 00:00:01 GMT';
    });

    describe('Sessions list on load', () => {
      localStorageStack.push({ name: 'name', pseudo: 'pseudo', token: 'token' });
      it('should handle angry /api/refresh', () => {
        let $scope = $rootScope.$new();
        $controller('HomeController', { $scope: $scope });

        $httpBackend.expectGET('/api/list').respond(402, '{"error":"Error"}');

        $httpBackend.flush();
        expect($scope.error).to.equal('Error');
      });

      localStorageStack.push({ name: 'name', pseudo: 'pseudo', token: 'token' });
      it('should logout if refused /api/refresh', () => {
        let $scope = $rootScope.$new();
        $controller('HomeController', { $scope: $scope });

        $httpBackend.expectGET('/api/list').respond(401, '{"error":"Not logged in"}');
        $httpBackend.expectGET('/api/logout').respond(201, '');
        $httpBackend.expectGET('login.inc.html').respond(201, '');

        $httpBackend.flush();
      });

      localStorageStack.push({ name: 'name', pseudo: 'pseudo', token: 'token' });
      it('should list current sessions', () => {
        let $scope = $rootScope.$new();
        $controller('HomeController', { $scope: $scope });

        $httpBackend.expectGET('/api/list').respond(201, '[{"sid":"xx1","ip":"1.1.1.1","ua":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.2 (KHTML, like Gecko) Ubuntu/11.10 Chromium/15.0.874.106 Chrome/15.0.874.106 Safari/535.2","lastUsed":0},{"sid":"xx2","ip":"2.2.2.2","ua":"Mozilla/5.0 (Linux; U; Android 2.3.4; en-us; Sprint APA7373KT Build/GRJ22) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0","lastUsed":0}]');
        $httpBackend.expectGET('https://geoip.tools/v1/json/?q=1.1.1.1').respond(201, '{"city":"City1","region_name":"Region1","country_name":"Country1"}');
        $httpBackend.expectGET('https://geoip.tools/v1/json/?q=2.2.2.2').respond(201, '{"city":"City2","region_name":"Region2","country_name":"Country2"}');

        $httpBackend.flush();
        expect($scope.sessions).to.have.length(2);
        expect($scope.sessions[0].deviceType).to.equal('desktop');
        expect($scope.sessions[1].deviceType).to.equal('mobile');
        expect($scope.sessions[0].location).to.equal('City1 (Region1 / Country1)');
        expect($scope.sessions[1].location).to.equal('City2 (Region2 / Country2)');
      });
    });

    describe('$scope.disconnect', () => {
      localStorageStack.push({ name: 'name', pseudo: 'pseudo', token: 'token' });
      it('should handle angry /api/remove', () => {
        let $scope = $rootScope.$new();
        $controller('HomeController', { $scope: $scope });

        $httpBackend.expectGET('/api/list').respond(201, '[{"sid":"xx1","ip":"1.1.1.1","ua":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.2 (KHTML, like Gecko) Ubuntu/11.10 Chromium/15.0.874.106 Chrome/15.0.874.106 Safari/535.2","lastUsed":0},{"sid":"xx2","ip":"2.2.2.2","ua":"Mozilla/5.0 (Linux; U; Android 2.3.4; en-us; Sprint APA7373KT Build/GRJ22) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0","lastUsed":0}]');
        $httpBackend.expectPOST('/api/remove', '{"sid":"xx1"}').respond(402, '{"error":"Error"}');
        $httpBackend.expectGET('https://geoip.tools/v1/json/?q=1.1.1.1').respond(201, '{"city":"City1","region_name":"Region1","country_name":"Country1"}');
        $httpBackend.expectGET('https://geoip.tools/v1/json/?q=2.2.2.2').respond(201, '{"city":"City2","region_name":"Region2","country_name":"Country2"}');

        $scope.disconnect('xx1');

        $httpBackend.flush();
        expect($scope.sessions).to.have.length(2);
        expect($scope.error).to.equal('Error');
      });

      localStorageStack.push({ name: 'name', pseudo: 'pseudo', token: 'token' });
      it('should disconnect specific session', () => {
        let $scope = $rootScope.$new();
        $controller('HomeController', { $scope: $scope });

        $httpBackend.expectGET('/api/list').respond(201, '[{"sid":"xx1","ip":"1.1.1.1","ua":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.2 (KHTML, like Gecko) Ubuntu/11.10 Chromium/15.0.874.106 Chrome/15.0.874.106 Safari/535.2","lastUsed":0},{"sid":"xx2","ip":"2.2.2.2","ua":"Mozilla/5.0 (Linux; U; Android 2.3.4; en-us; Sprint APA7373KT Build/GRJ22) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0","lastUsed":0}]');
        $httpBackend.expectPOST('/api/remove', '{"sid":"xx1"}').respond(201, '');
        $httpBackend.expectGET('https://geoip.tools/v1/json/?q=1.1.1.1').respond(201, '{"city":"City1","region_name":"Region1","country_name":"Country1"}');
        $httpBackend.expectGET('https://geoip.tools/v1/json/?q=2.2.2.2').respond(201, '{"city":"City2","region_name":"Region2","country_name":"Country2"}');
        $httpBackend.expectGET('/api/list').respond(201, '[{"sid":"xx2","ip":"2.2.2.2","ua":"Mozilla/5.0 (Linux; U; Android 2.3.4; en-us; Sprint APA7373KT Build/GRJ22) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0","lastUsed":0}]');
        $httpBackend.expectGET('https://geoip.tools/v1/json/?q=2.2.2.2').respond(201, '{"city":"City2","region_name":"Region2","country_name":"Country2"}');

        $scope.disconnect('xx1');

        $httpBackend.flush();
        expect($scope.sessions).to.have.length(1);
      });
    });

    describe('$scope.flush', () => {
      localStorageStack.push({ name: 'name', pseudo: 'pseudo', token: 'token' });
      it('should handle angry /api/flush', () => {
        let $scope = $rootScope.$new();
        $controller('HomeController', { $scope: $scope });

        $httpBackend.expectGET('/api/list').respond(201, '[{"sid":"xx1","ip":"1.1.1.1","ua":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.2 (KHTML, like Gecko) Ubuntu/11.10 Chromium/15.0.874.106 Chrome/15.0.874.106 Safari/535.2","lastUsed":0},{"sid":"xx2","ip":"2.2.2.2","ua":"Mozilla/5.0 (Linux; U; Android 2.3.4; en-us; Sprint APA7373KT Build/GRJ22) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0","lastUsed":0}]');
        $httpBackend.expectGET('/api/flush').respond(402, '{"error":"Error"}');
        $httpBackend.expectGET('https://geoip.tools/v1/json/?q=1.1.1.1').respond(201, '{"city":"City1","region_name":"Region1","country_name":"Country1"}');
        $httpBackend.expectGET('https://geoip.tools/v1/json/?q=2.2.2.2').respond(201, '{"city":"City2","region_name":"Region2","country_name":"Country2"}');

        $scope.flush();

        $httpBackend.flush();
        expect($scope.sessions).to.have.length(2);
        expect($scope.error).to.equal('Error');
      });

      localStorageStack.push({ name: 'name', pseudo: 'pseudo', token: 'token' });
      it('should disconnect other session(s)', () => {
        let $scope = $rootScope.$new();
        $controller('HomeController', { $scope: $scope });

        $httpBackend.expectGET('/api/list').respond(201, '[{"sid":"xx1","ip":"1.1.1.1","ua":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.2 (KHTML, like Gecko) Ubuntu/11.10 Chromium/15.0.874.106 Chrome/15.0.874.106 Safari/535.2","lastUsed":0},{"sid":"xx2","ip":"2.2.2.2","ua":"Mozilla/5.0 (Linux; U; Android 2.3.4; en-us; Sprint APA7373KT Build/GRJ22) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0","lastUsed":0}]');
        $httpBackend.expectGET('/api/flush').respond(201, '');
        $httpBackend.expectGET('https://geoip.tools/v1/json/?q=1.1.1.1').respond(201, '{"city":"City1","region_name":"Region1","country_name":"Country1"}');
        $httpBackend.expectGET('https://geoip.tools/v1/json/?q=2.2.2.2').respond(201, '{"city":"City2","region_name":"Region2","country_name":"Country2"}');
        $httpBackend.expectGET('/api/list').respond(201, '[{"sid":"xx2","ip":"2.2.2.2","ua":"Mozilla/5.0 (Linux; U; Android 2.3.4; en-us; Sprint APA7373KT Build/GRJ22) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0","lastUsed":0}]');
        $httpBackend.expectGET('https://geoip.tools/v1/json/?q=2.2.2.2').respond(201, '{"city":"City2","region_name":"Region2","country_name":"Country2"}');

        $scope.flush();

        $httpBackend.flush();
        expect($scope.sessions).to.have.length(1);
      });
    });
  });

  describe('LoginController', () => {
    var $httpBackend, $controller, $rootScope;
    var localStorageStack = [ ];

    beforeEach(() => {
      dom.reconfigure({ url: 'http://example.org/#/login' });
      window.localStorage.setItem('ls.authInfo', JSON.stringify(localStorageStack.shift()));

      ngModule('cerberus');
      ngInject(($location, _$httpBackend_, _$controller_, _$rootScope_) => {
        $httpBackend = _$httpBackend_;
        $controller = _$controller_;
        $rootScope = _$rootScope_;

        $location.path('/login');
        $httpBackend.expectGET('login.inc.html').respond(201, '');
        $rootScope.$digest();
      });
    });

    afterEach(() => {
      $httpBackend.verifyNoOutstandingExpectation();
      $httpBackend.verifyNoOutstandingRequest();

      window.localStorage.removeItem('ls.authInfo');
      window.document.cookie = 'cerberus=;expires=Thu, 01 Jan 1970 00:00:01 GMT';
    });

    describe('Initialize', () => {
      localStorageStack.push({ name: 'name', pseudo: 'pseudo', token: 'token' });
      it('should go to home if already logged-in', () => {
        let $scope = $rootScope.$new();
        $controller('LoginController', { $scope: $scope });

        $httpBackend.expectGET('home.inc.html').respond(201, '');

        $httpBackend.flush();
      });

      localStorageStack.push(null);
      it('should read redirect cookie if present', () => {
        window.document.cookie = 'redirect=http://sub.example.org/page';
        let $scope = $rootScope.$new();
        $controller('LoginController', { $scope: $scope });

        $httpBackend.flush();
        expect($scope.redirect).to.equal('http://sub.example.org/page');
        expect(window.document.cookie).to.equal('');
      });

      localStorageStack.push(null);
      it('should focus on "pseudo" INPUT element', () => {
        let $scope = $rootScope.$new();
        $controller('LoginController', { $scope: $scope });

        $httpBackend.flush();
        expect(window.document.activeElement.name).to.equal('pseudo-input');
      });
    });

    describe('$scope.login', () => {
      localStorageStack.push(null);
      it('should show error if any', () => {
        let $scope = $rootScope.$new();
        $controller('LoginController', { $scope: $scope });

        $httpBackend.expectPOST('/api/prelogin').respond(200, '{"c":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}');
        $httpBackend.expectPOST('/api/login').respond(402, '{"error":"Error"}');

        $scope.login('pseudo', 'password', '000000');

        $httpBackend.flush();
        expect($scope.error).to.equal('Error');
      });

      localStorageStack.push(null);
      it('should login and redirect if cookie present', () => {
        window.document.cookie = 'redirect=http://sub.example.org/page';
        let $scope = $rootScope.$new();
        $controller('LoginController', { $scope: $scope });

        $httpBackend.expectPOST('/api/prelogin').respond(200, '{"c":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}');
        $httpBackend.expectPOST('/api/login').respond(201, '');

        let orig = window.location;
        delete window.location;
        window.location = { assign: href => {
          expect(href).to.equal('http://sub.example.org/page');
          window.location = orig;
        } };

        $scope.login('pseudo', 'password', '000000');

        $httpBackend.flush();
      });

      localStorageStack.push(null);
      it('should login and go home if not', () => {
        let $scope = $rootScope.$new();
        $controller('LoginController', { $scope: $scope });

        $httpBackend.expectPOST('/api/prelogin').respond(200, '{"c":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}');
        $httpBackend.expectPOST('/api/login').respond(201, '');
        $httpBackend.expectGET('home.inc.html').respond(201, '');

        $scope.login('pseudo', 'password', '000000');

        $httpBackend.flush();
      });
    });
  });

  describe('GenerateController', () => {
    var $httpBackend, $controller, $rootScope;
    var localStorageStack = [ ], gid;

    beforeEach(() => {
      gid = randomBytes(32).toString('hex');
      dom.reconfigure({ url: 'http://example.org/#/generate/' + gid });
      window.localStorage.setItem('ls.authInfo', JSON.stringify(localStorageStack.shift()));

      ngModule('cerberus');
      ngInject(($location, _$httpBackend_, _$controller_, _$rootScope_) => {
        $httpBackend = _$httpBackend_;
        $controller = _$controller_;
        $rootScope = _$rootScope_;

        $location.path('/generate/' + gid);
        $httpBackend.expectGET('generate.inc.html').respond(201, '');
        $rootScope.$digest();
      });
    });

    afterEach(() => {
      $httpBackend.verifyNoOutstandingExpectation();
      $httpBackend.verifyNoOutstandingRequest();

      window.localStorage.removeItem('ls.authInfo');
      window.document.cookie = 'cerberus=;expires=Thu, 01 Jan 1970 00:00:01 GMT';
    });

    describe('Initialize', () => {
      localStorageStack.push({ name: 'name', pseudo: 'pseudo', token: 'token' });
      it('should go to home if already logged-in', () => {
        let $scope = $rootScope.$new();
        $controller('GenerateController', { $scope: $scope });

        $httpBackend.expectGET('home.inc.html').respond(201, '');

        $httpBackend.flush();
      });

      localStorageStack.push(null);
      it('should go to login if angry /api/geninfo', () => {
        let $scope = $rootScope.$new();
        $controller('GenerateController', { $scope: $scope });

        $httpBackend.expectPOST('/api/geninfo').respond(402, '');
        $httpBackend.expectGET('login.inc.html').respond(201, '');

        $httpBackend.flush();
      });

      localStorageStack.push(null);
      it('should fill-in information from /api/geninfo', () => {
        let $scope = $rootScope.$new();
        $controller('GenerateController', { $scope: $scope });
        let pseudo = randomstring.generate(8);
        let otpkey = randomstring.generate(8);
        let otpauth = 'otpauth://totp/cerberus:' + pseudo + '?secret=' + otpkey + '&issuer=cerberus';

        $httpBackend.expectPOST('/api/geninfo').respond(200, '{"pseudo":"' + pseudo + '","qrcode":"' + otpauth + '"}');

        $httpBackend.flush();
        expect($scope.pseudo).to.equal(pseudo);
        expect($scope.qrcode).to.equal(otpauth);
      });
    });

    describe('$scope.generate', () => {
      localStorageStack.push(null);
      it('should complain if password don\'t match', () => {
        let $scope = $rootScope.$new();
        $controller('GenerateController', { $scope: $scope });
        let pseudo = randomstring.generate(8);
        let otpkey = randomstring.generate(8);
        let otpauth = 'otpauth://totp/cerberus:' + pseudo + '?secret=' + otpkey + '&issuer=cerberus';

        $httpBackend.expectPOST('/api/geninfo').respond(200, '{"pseudo":"' + pseudo + '","qrcode":"' + otpauth + '"}');

        $scope.generate(pseudo, 'passwd', 'passwd2', '000000');

        $httpBackend.flush();
        expect($scope.error).to.equal('Passwords don\'t match');
      });

      localStorageStack.push(null);
      it('should handle auth.generate error', () => {
        let $scope = $rootScope.$new();
        $controller('GenerateController', { $scope: $scope });
        let pseudo = randomstring.generate(8);
        let otpkey = randomstring.generate(8);
        let otpauth = 'otpauth://totp/cerberus:' + pseudo + '?secret=' + otpkey + '&issuer=cerberus';

        $httpBackend.expectPOST('/api/geninfo').respond(200, '{"pseudo":"' + pseudo + '","qrcode":"' + otpauth + '"}');
        $httpBackend.expectPOST('/api/generate').respond(402, '{"error":"Error"}');

        $scope.generate(pseudo, 'passwd', 'passwd', '000000');

        $httpBackend.flush();
        expect($scope.error).to.equal('Error');
      });

      localStorageStack.push(null);
      it('should go home if generation is validated', () => {
        let $scope = $rootScope.$new();
        $controller('GenerateController', { $scope: $scope });
        let token = randomBytes(12).toString('hex');
        let pseudo = randomstring.generate(8);
        let name = randomstring.generate(12);
        let otpkey = randomstring.generate(8);
        let otpauth = 'otpauth://totp/cerberus:' + pseudo + '?secret=' + otpkey + '&issuer=cerberus';

        $httpBackend.expectPOST('/api/geninfo').respond(200, '{"pseudo":"' + pseudo + '","qrcode":"' + otpauth + '"}');
        $httpBackend.expectPOST('/api/generate').respond(200, JSON.stringify({ name, pseudo, token }));
        $httpBackend.expectGET('home.inc.html').respond(201, '');

        $scope.generate(pseudo, 'passwd', 'passwd', '000000');

        $httpBackend.flush();
        expect(window.document.cookie).to.equal('cerberus=' + token);
      });
    });
  });
});
