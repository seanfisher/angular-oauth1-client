/*! angular-oauth1-client - v0.1.10 - 2016-02-01
* Copyright (c) 2016 Sean Fisher; Licensed MIT */
(function(window, angular, undefined) {'use strict';

angular.module('oauth1Client', ['LocalStorageModule'])

.service('oauthPersistence', ['localStorageService', '$q', function(localStorageService, $q){

    var self = this;
    var OAUTH_TOKEN_KEY = "oauth_token";
    var OAUTH_TOKEN_SECRET_KEY = "oauth_token_secret";

    self.storeAccessToken = function(access_data) {
        var defer = $q.defer();
        localStorageService.set(OAUTH_TOKEN_KEY, access_data.oauth_token);
        localStorageService.set(OAUTH_TOKEN_SECRET_KEY, access_data.oauth_token_secret);

        defer.resolve();
        return defer.promise;
    };

    self.clearAccessToken = function(){
        localStorageService.remove(OAUTH_TOKEN_KEY);
        localStorageService.remove(OAUTH_TOKEN_SECRET_KEY);
    };

    self.accessIsInStorage = function(isAuthenticated, isNotAuthenticated){
        if (localStorageService.get(OAUTH_TOKEN_KEY) && localStorageService.get(OAUTH_TOKEN_SECRET_KEY)) {
            isAuthenticated();
        } else {
            isNotAuthenticated();
        }

    };

    self.getTokenAndSecret = function(onCompletion){
        onCompletion(localStorageService.get(OAUTH_TOKEN_KEY), localStorageService.get(OAUTH_TOKEN_SECRET_KEY));
    };
}])

.factory('oauth1Signer', [function oauth1SignerFactory() {
    function randomString(length) {
        var text = "";
        var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        for(var i = 0; i < length; i++) {
            text += possible.charAt(Math.floor(Math.random() * possible.length));
        }
        return text;
    }

    return {
        create: function(parameters) {
            // Adapted from https://github.com/7digital/oauth-reference-page/blob/gh-pages/oauth.js
            return _.extend({
                token: null,
                tokenSecret: "",
                version: "1.0",
                signatureMethod: "HMAC-SHA1",
                method: "GET",
                timestamp: Math.floor(Date.now() / 1000),
                nonce: randomString(32),
                oauthParameters: function() {
                    var self, queryFields;
                    self = this;
                    queryFields = {
                        oauth_consumer_key: self.consumerKey,
                        oauth_nonce: self.nonce,
                        oauth_timestamp: self.timestamp,
                        oauth_signature_method: self.signatureMethod
                    };
                    if (self.token) {
                        queryFields.oauth_token = self.token;
                    }
                    if (self.version) {
                        queryFields.oauth_version = self.version;
                    }
                    if (self.callbackUrl) {
                        queryFields.oauth_callback = self.callbackUrl;
                    }
                    if (self.verifier) {
                        queryFields.oauth_verifier = self.verifier;
                    }
                    if (self.scopes) {
                        queryFields.scopes = self.scopes;
                    }
                    return queryFields;
                },
                queryStringFields: function() {
                    var self, queryFields, fields;
                    self = this;
                    queryFields = self.oauthParameters();
                    fields = self.fields;
                    _.each(_.keys(fields), function(field) {
                        return queryFields[field] = fields[field];
                    });
                    return queryFields;
                },
                queryString: function() {
                    var self, queryArguments, orderedFields;
                    self = this;
                    queryArguments = self.queryStringFields();
                    orderedFields = _.keys(queryArguments).sort();
                    var queryString = _.map(orderedFields, function(fieldName) {
                        return fieldName + "=" + self.percentEncode(queryArguments[fieldName]);
                    }).join("&");
                    return queryString;
                },
                urlEncoded: function(fields) {
                    return _.map(_.keys(fields), function(fieldName) {
                        return fieldName + "=" + encodeURIComponent(fields[fieldName]);
                    }).join("&");
                },
                headerEncoded: function(fields) {
                    return _.map(_.keys(fields), function(fieldName) {
                        return fieldName + '="' + encodeURIComponent(fields[fieldName]) + '"';
                    }).join(", ");
                },
                urlEncodedFields: function() {
                    var self;
                    self = this;
                    return self.urlEncoded(self.fields);
                },
                authorizationHeader: function() {
                    var self, fields;
                    self = this;
                    fields = self.oauthParameters();
                    fields.oauth_signature = self.base64Signature();
                    return self.headerEncoded(fields);
                },
                urlAndFields: function() {
                    var self, encodedFields;
                    self = this;
                    encodedFields = self.urlEncodedFields();
                    if (encodedFields) {
                        return self.url + "?" + encodedFields;
                    } else {
                        return self.url;
                    }
                },
                parameterEncoded: function(fields) {
                    var self = this;
                    var strToSign =
                    _.map(fields, function(field) {
                        return self.percentEncode(field);
                    }).join("&");
                    return strToSign;
                },
                baseString: function() {
                    var self;
                    self = this;
                    return self.parameterEncoded([ self.method, self.url, self.queryString() ]);
                },
                hmacKey: function() {
                    var self;
                    self = this;
                    return self.parameterEncoded([ self.consumerSecret, self.tokenSecret ]);
                },
                hmac: function(gen1_options) {
                    var encoding, self;
                    encoding = gen1_options && gen1_options.hasOwnProperty("encoding") && gen1_options.encoding !== void 0 ? gen1_options.encoding : "binary";
                    self = this;
                    if (typeof process !== "undefined") {
                        var crypto, h;
                        crypto = require("crypto");
                        h = crypto.createHmac("sha1", self.hmacKey());
                        h.update(self.baseString());
                        return h.digest(encoding);
                    } else {
                        var binaryHash;
                        binaryHash = CryptoJS.HmacSHA1(self.baseString(), self.hmacKey());
                        if (encoding === "base64") {
                            return binaryHash.toString(CryptoJS.enc.Base64);
                        } else {
                            return binaryHash;
                        }
                    }
                },
                base64Signature: function() {
                    var self;
                    self = this;
                    return self.hmac({
                        encoding: "base64"
                    });
                },
                signature: function() {
                    var self;
                    self = this;
                    return self.percentEncode(self.base64Signature());
                },
                signedUrl: function() {
                    var self;
                    self = this;
                    return self.url + "?" + self.queryString() + "&oauth_signature=" + self.signature();
                },
                curl: function() {
                    var self;
                    self = this;
                    if (self.method() === "GET") {
                        return "curl '" + self.url + "?" + self.queryString() + "&oauth_signature=" + self.signature() + "'";
                    } else if (self.method() === "POST" || self.method() === "PUT") {
                        if (self.body()) {
                            return "curl -X " + self.method() + " '" + self.urlAndFields() + "' -d '" + self.body() + "' -H 'Authorization: " + self.authorizationHeader() + "' -H 'Content-Type: " + self.bodyEncoding() + "'";
                        } else {
                            return "curl -X " + self.method() + " '" + self.url + "' -d '" + self.queryString() + "&oauth_signature=" + self.signature() + "'";
                        }
                    } else {
                        return "curl -X DELETE '" + self.url + "?" + self.queryString() + "&oauth_signature=" + self.signature() + "'";
                    }
                },
                percentEncode: function(s) {
                    return encodeURIComponent(s).replace(/\*/g, "%2A");
                }
            }, parameters);
        }
    };
}])

.provider('oauth1Client', function oauth1ClientProvider () {
    var consumerKey;
    var consumerSecret;
    var requestEndpoint;
    var authorizeEndpoint;
    var accessEndpoint;
    var oauthCallback;
    var requestToken;
    var requestTokenSecret;
    var scopes;

    this.config = function(settings) {
        consumerKey = settings.consumerKey;
        consumerSecret = settings.consumerSecret;
        requestEndpoint = settings.requestEndpoint;
        authorizeEndpoint = settings.authorizeEndpoint;
        accessEndpoint = settings.accessEndpoint;
        oauthCallback = settings.oauthCallback;
        scopes = settings.scopes;
    };

    // utility functions
    function getURLParameter(url, name) {
        var URLParamRegEx = new RegExp('[?|&]?' + name + '=([^&;]+?)(&|#|;|$)');
        var value = URLParamRegEx.exec(url);
        value = (value) ? value[1] : "";
        return decodeURIComponent(value.replace(/\+/g, '%20')) || null;
    }

    function randomString(length) {
        var text = "";
        var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        for(var i = 0; i < length; i++) {
            text += possible.charAt(Math.floor(Math.random() * possible.length));
        }
        return text;
    }

    if (typeof String.prototype.startsWith != 'function') {
        String.prototype.startsWith = function (str){
            return this.indexOf(str) === 0;
        };
    }

    this.$get = [
        '$q',
        '$http',
        'oauth1Signer',
        'oauth1Headers',
        'oauth1AuthorizedHttp',
        'oauthPersistence',
        function($q, $http, oauth1Signer, oauth1Headers, oauth1AuthorizedHttp, oauthPersistence) {

        var self = this;

        function getOAuthSigner(params) {
            return oauth1Signer.create(params);
        }

        function getRequestToken(oauthSigner, callback_url) {
            var deferred = $q.defer();
            $http.get(oauthSigner.signedUrl())
            .success(function(data, status, headers, config) {
                deferred.resolve({
                    oauth_token: getURLParameter(data, "oauth_token"),
                    oauth_token_secret: getURLParameter(data, "oauth_token_secret"),
                    oauth_callback_confirmed: getURLParameter(data, "oauth_callback_confirmed")
                });
            })
            .error(function(data, status, headers, config) {
                alert("getRequestTokenError: " + JSON.stringify(data));
                deferred.reject("getRequestTokenError: " + JSON.stringify(data));
            });
            return deferred.promise;
        }

        function getAuthorizationToken(oauth_token, callback_url, afterWindowOpen, beforeWindowClose, onLoad) {
            var deferred = $q.defer();

            var authorizationTokenUrl = authorizeEndpoint + "?oauth_token=" + oauth_token + "&oauth_callback=" + callback_url;
            var auth_window = window.open(authorizationTokenUrl, '_blank', 'location=no,clearcache=yes,hidden=yes');
            var visible = false;
            auth_window.addEventListener('loadstart', function(event) {
                if((event.url).startsWith(callback_url)) {
                    if(angular.isFunction(beforeWindowClose)){
                        beforeWindowClose();
                    }
                    auth_window.close();

                    deferred.resolve({
                        returned_oauth_token: getURLParameter(event.url, 'oauth_token'),
                        oauth_verifier: getURLParameter(event.url, 'oauth_verifier'),
                    });
                }
            });
            auth_window.addEventListener('loadstop', function(event) {
                if(angular.isFunction(onLoad)) {
                    onLoad(auth_window, event);
                }
                if(!visible) {
                    auth_window.show();
                    visible = true;
                }
                if(angular.isFunction(afterWindowOpen)){
                    afterWindowOpen();
                }
            });
            return deferred.promise;
        }

        function getAccessToken(oauthSigner) {
            var deferred = $q.defer();
            $http.post(oauthSigner.signedUrl())
            .success(function(data, status, headers, config) {
                deferred.resolve({
                    oauth_token: getURLParameter(data, "oauth_token"),
                    oauth_token_secret: getURLParameter(data, 'oauth_token_secret')
                });
            })
            .error(function(data, status, headers, config) {
                alert("getAccessTokenError: " + JSON.stringify(data));
                deferred.reject("getAccessTokenError: " + JSON.stringify(data));
            });
            return deferred.promise;
        }

        function checkAuthenticated(isAuthenticated, isNotAuthenticated) {
            oauthPersistence.accessIsInStorage(isAuthenticated, isNotAuthenticated);
        }

        function getAuthorizedHttp(onCompletion, access_data) {
            var oauth_token = access_data.oauth_token;
            var oauth_token_secret = access_data.oauth_token_secret;
            var signer = getOAuthSigner({
                url : requestEndpoint,
                consumerKey : consumerKey,
                consumerSecret : consumerSecret,
                token : oauth_token,
                tokenSecret : oauth_token_secret
            });

            oauth1Headers.create(signer);
            onCompletion(oauth1AuthorizedHttp.create(signer));
        }

        return {
            oAuthSigner: function(onCompletion) {
                oauthPersistence.getTokenAndSecret(function (oauth_token, oauth_token_secret){
                    onCompletion(getOAuthSigner({
                        url : requestEndpoint,
                        consumerKey : consumerKey,
                        consumerSecret : consumerSecret,
                        token : oauth_token,
                        tokenSecret : oauth_token_secret
                    }));
                });
            },
            authorize: function(afterWindowOpen, beforeWindowClose, onLoad) {
                var deferred = $q.defer();

                var oauthSigner = getOAuthSigner({
                    url : requestEndpoint,
                    consumerKey : consumerKey,
                    consumerSecret : consumerSecret,
                    callbackUrl : oauthCallback,
                    scopes : scopes
                });
                var authObj = oauthSigner.oauthParameters();
                getRequestToken(oauthSigner, oauthCallback)
                .then(function(request_data) {
                    requestToken = request_data.oauth_token;
                    requestTokenSecret = request_data.oauth_token_secret;
                    return getAuthorizationToken(request_data.oauth_token, oauthCallback, afterWindowOpen, beforeWindowClose, onLoad);
                })
                .then(function(authorization_data) {
                    oauthSigner = getOAuthSigner({
                        url : accessEndpoint,
                        consumerKey : consumerKey,
                        consumerSecret : consumerSecret,
                        method : "POST",
                        token : requestToken,
                        tokenSecret : requestTokenSecret,
                        verifier : authorization_data.oauth_verifier
                    });
                    return getAccessToken(oauthSigner);
                })
                .then(function(access_data) {
                    oauthPersistence.storeAccessToken(access_data).then(function(){
                        getAuthorizedHttp(function(item) {deferred.resolve(item);}, access_data);
                    });
                }, function(error) {
                    alert('Error: ' + JSON.stringify(error));
                    deferred.resolve({'error': JSON.stringify(error)});
                });
                return deferred.promise;
            }
        };
    }];
})

.service('oauth1AuthorizedHttp', ['$http', '$q', function oauth1AuthorizedHttpService($http, $q) {
    return {
        create: function(signer) {
            this.oauth1Signer = signer;
            var self = this;
            return function(config) {
                self.oauth1Signer.method = config.method || "GET";
                self.oauth1Signer.url = config.url;
                $http.defaults.headers.common.Authorization = "OAuth " + self.oauth1Signer.authorizationHeader();
                $http.defaults.headers.common['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8';
                var defer = $q.defer();
                $http(config).then(
                    function(response){
                        response.data.authToken = self.oauth1Signer.token;
                        defer.resolve(response);
                    },
                    function(response){
                        defer.reject(response);
                    }
                );

                return defer.promise;
            };
        }
    };
}])

.service('oauth1Headers', ['$http', function oauth1HeadersService($http) {
    return {
        create: function(signer) {
            this.oauth1Signer = signer;
            var self = this;
        },
        getHeaders: function(url, method) {
            var self = this;
            if(self.oauth1Signer){
                self.oauth1Signer.method = method;
                self.oauth1Signer.url = url;
                return {'Authorization' : "OAuth " + self.oauth1Signer.authorizationHeader(),
                    'Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'
                };
            }
            else {
                return {'Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'};
            }
        },
        removeAuthorizationHeader: function() {
            $http.defaults.headers.common.Authorization = undefined;
        }
    };
}])

;

})(window, window.angular);
