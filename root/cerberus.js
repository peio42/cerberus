angular.module('cerberus', [ 'ngCookies', 'ui.router', 'LocalStorageModule', 'monospaced.qrcode' ])

  .config(['$stateProvider', '$urlRouterProvider', function($stateProvider, $urlRouterProvider) {
    $urlRouterProvider.otherwise('/');

    $stateProvider
      .state('home', {
        url: '/',
        templateUrl: 'home.inc.html',
        controller: 'HomeController',
        data: { requireLoggedIn: true },
      })
      .state('login', {
        url: '/login',
        templateUrl: 'login.inc.html',
        controller: 'LoginController',
        data: { requireLoggedIn: false },
      })
      .state('generate', {
        url: '/generate/:gid',
        templateUrl: 'generate.inc.html',
        controller: 'GenerateController',
        data: { requireLoggedIn: false },
      })
    ;
  }])

  .factory('auth', [ '$q', '$http', '$cookies', 'localStorageService', function($q, $http, $cookies, localStorageService) {
    const domain = '.' + window.location.hostname.split('.').slice(-2).join('.');
    var authInfo;

    if (localStorageService.isSupported && (authInfo = localStorageService.get('authInfo'))) {
      $cookies.put('cerberus', authInfo.token, { expires: (new Date().getTime() + 42*24*3600*1000), domain: domain });
    } else
      authInfo = { };

    return {
      login: function(pseudo, passwd, gotp) {
        return $q(function(resolve, reject) {
          $http.post('/api/prelogin', { l: pseudo }).then(
            function(resp) {
              var key = new sjcl.ecc.ecdsa.secretKey(sjcl.ecc.curves.k256, sjcl.bn.fromBits(sjcl.hash.ripemd160.hash(sjcl.misc.pbkdf2(passwd, pseudo, 42))));
              $http.post('/api/login', { l: pseudo, r: sjcl.codec.hex.fromBits(key.sign(sjcl.codec.hex.toBits(resp.data.c))), g: gotp }).then(
                function(resp) {
                  setAuthInfo(resp.data);
                  resolve();
                },
                function(resp) { reject(resp.data.error); }
              );
            },
            function(resp) { reject(resp.data.error); });
        });
      },

      logout: function() {
        return $q(function(resolve, reject) {
          $http.get('/api/logout').then(function(resp) {
            clearAuthInfo();
            resolve();
          }, function(resp) {
            reject(resp.data.error);
          });
        });
      },

      generate: function(gid, pseudo, passwd, gotp) {
        return $q(function(resolve, reject) {
          var key = sjcl.ecc.ecdsa.generateKeys(sjcl.ecc.curves.k256, 0, sjcl.bn.fromBits(sjcl.hash.ripemd160.hash(sjcl.misc.pbkdf2(passwd, pseudo, 42)))).pub.get();
          $http.post('/api/generate', { gid: gid, k: '04' + sjcl.codec.hex.fromBits(key.x) + sjcl.codec.hex.fromBits(key.y), g: gotp }).then(
            function(resp) {
              setAuthInfo(resp.data);
              resolve();
            },
            function(resp) { reject(resp.data.error); }
          );
        });
      },

      isLoggedIn: function() {
        return authInfo.token !== undefined;
      },

      pseudo: function() {
        return authInfo.pseudo;
      },

      name: function() {
        return authInfo.name;
      },
    };

    function setAuthInfo(info) {
      authInfo = info;
      if (localStorageService.isSupported)
        localStorageService.set('authInfo', info);
      $cookies.put('cerberus', info.token, { expires: (new Date().getTime() + 42*24*3600*1000), domain: domain });
    }

    function clearAuthInfo() {
      authInfo = { };
      if (localStorageService.isSupported)
        localStorageService.remove('authInfo');
      $cookies.remove('cerberus');
    }
  }])

  .controller('WidgetController', ['$scope', '$state', 'auth', function($scope, $state, auth) {
    $scope.auth = auth;
    $scope.logout = function() { auth.logout().then(function() { $state.go('login'); }) };
  }])

  .controller('HomeController', ['$scope', '$state', '$http', 'auth', function($scope, $state, $http, auth) {
    refresh();
    $scope.disconnect = function (sid) { $http.post('/api/remove', { sid: sid }).then(refresh()) };
    $scope.flush = function() { $http.get('/api/flush').then(refresh) };

    function refresh() {
      $http.get('/api/list').then(
        function(resp) {
          $scope.sessions = resp.data;
          $scope.sessions.forEach(function (s) {
            $http.get('https://geoip.tools/v1/json/?q=' + s.ip).then(function(resp) {
              s.location = resp.data.city + ' (' + resp.data.region_name + ' / ' + resp.data.country_name + ')';
            });
            s.ua = UAParser(s.ua);
            s.deviceType = s.ua.device.type || 'desktop';
            s.dt = new Date(s.lastUsed).toString();
          });
        },
        function(resp) {
          if (resp.status == 401)
            auth.logout().then(function() { $state.go('login'); });
          else
            $scope.error = resp.data.error;
        });
    }
  }])

  .controller('LoginController', ['$scope', '$state', '$cookies', '$window', 'auth', function($scope, $state, $cookies, $window, auth) {
    auth.isLoggedIn() && $state.go('home');

    $scope.login = function(pseudo, passwd, gotp) {
      auth.login(pseudo, passwd, gotp).then(
        function() {
          if ($scope.redirect !== undefined)
            $window.location.href = 'https://' + $scope.redirect;
          else
            $state.go('home');
        },
        function(error) { $scope.error = error }
      );
    };
    $scope.redirect = $cookies.get('redirect');
    $cookies.remove('redirect');
    document.querySelector('[ng-model="pseudo"]').focus();
  }])

  .controller('GenerateController', ['$scope', '$http', '$state', '$stateParams', 'auth', function($scope, $http, $state, $stateParams, auth) {
    auth.isLoggedIn() && $state.go('home');

    $http.post('/api/geninfo', { gid: $stateParams.gid }).then(
      function(resp) {
        $scope.pseudo = resp.data.pseudo;
        $scope.qrcode = resp.data.qrcode;
      },
      function(resp) { $state.go('login'); }
    );

    $scope.generate = function(pseudo, passwd, passwd2, gotp) {
      if (passwd != passwd2) {
        $scope.error = "Passwords don't match";
        return ;
      }
      delete $scope.error;

      auth.generate($stateParams.gid, pseudo, passwd, gotp).then(
        function() { $state.go('home'); },
        function(error) { $scope.error = error; }
      );
    };
  }])

;
