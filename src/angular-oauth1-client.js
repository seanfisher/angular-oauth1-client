/*global window: false */
(function(window, angular, undefined) {'use strict';

angular.module('oauth1Client', ['LocalStorageModule'])

.service('oauthPersistence', ['localStorageService', '$q', function(localStorageService, $q){
    // drop $q/promises since localStorageService works synchronously

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
            return angular.extend({
                token: null,
                tokenSecret: "",
                version: "1.0",
                signatureMethod: "HMAC-SHA1",
                method: "GET",
                timestamp: Math.floor(Date.now() / 1000),
                nonce: randomString(32),
                oauthParameters: function() {
                    var queryFields = {
                        oauth_consumer_key: this.consumerKey,
                        oauth_nonce: this.nonce,
                        oauth_timestamp: this.timestamp,
                        oauth_signature_method: this.signatureMethod
                    };
                    if (this.token) {
                        queryFields.oauth_token = this.token;
                    }
                    if (this.version) {
                        queryFields.oauth_version = this.version;
                    }
                    if (this.callbackUrl) {
                        queryFields.oauth_callback = this.callbackUrl;
                    }
                    if (this.verifier) {
                        queryFields.oauth_verifier = this.verifier;
                    }
                    if (this.scopes) {
                        queryFields.scopes = this.scopes;
                    }
                    return queryFields;
                },
                queryStringFields: function() {
                    var queryFields = this.oauthParameters();
                    var fields = this.fields;
                    Object.keys(fields || {}).map(function(field) {
                        return queryFields[field] = fields[field];
                    });
                    return queryFields;
                },
                queryString: function() {
                    var self = this;
                    var queryArguments = self.queryStringFields();
                    return Object.keys(queryArguments).sort().map(function (fieldName) {
                        return fieldName + "=" + self.percentEncode(queryArguments[fieldName]);
                    }).join("&");
                },
                urlEncoded: function(fields) {
                    return Object.keys(fields).map(function(fieldName) {
                        return fieldName + "=" + encodeURIComponent(fields[fieldName]);
                    }).join("&");
                },
                headerEncoded: function(fields) {
                    return Object.keys(fields).map(function(fieldName) {
                        return fieldName + '="' + encodeURIComponent(fields[fieldName]) + '"';
                    }).join(", ");
                },
                urlEncodedFields: function() {
                    return this.urlEncoded(this.fields);
                },
                authorizationHeader: function() {
                    var fields = this.oauthParameters();
                    fields.oauth_signature = this.base64Signature();
                    return this.headerEncoded(fields);
                },
                urlAndFields: function() {
                    var encodedFields = this.urlEncodedFields();
                    if (encodedFields) {
                        return this.url + "?" + encodedFields;
                    } else {
                        return this.url;
                    }
                },
                parameterEncoded: function(fields) {
                    var self = this;
                    return fields.map(function(field) {
                        return self.percentEncode(field);
                    }).join("&");
                },
                baseString: function() {
                    return this.parameterEncoded([ this.method, this.url, this.queryString() ]);
                },
                hmacKey: function() {
                    return this.parameterEncoded([ this.consumerSecret, this.tokenSecret ]);
                },
                hmac: function(gen1_options) {
                    var encoding = gen1_options && gen1_options.hasOwnProperty("encoding") && gen1_options.encoding !== void 0 ? gen1_options.encoding : "binary";
                    if (typeof process !== "undefined") {
                        /* global require */
                        var crypto, h;
                        crypto = require("crypto");
                        h = crypto.createHmac("sha1", this.hmacKey());
                        h.update(this.baseString());
                        return h.digest(encoding);
                    } else {
                        /* global CryptoJS */
                        var binaryHash;
                        binaryHash = CryptoJS.HmacSHA1(this.baseString(), this.hmacKey());
                        if (encoding === "base64") {
                            return binaryHash.toString(CryptoJS.enc.Base64);
                        } else {
                            return binaryHash;
                        }
                    }
                },
                base64Signature: function() {
                    return this.hmac({
                        encoding: "base64"
                    });
                },
                signature: function() {
                    return this.percentEncode(this.base64Signature());
                },
                signedUrl: function() {
                    return this.url + "?" + this.queryString() + "&oauth_signature=" + this.signature();
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

    if (!angular.isFunction(String.prototype.startsWith)) {
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

        function getOAuthSigner(params) {
            return oauth1Signer.create(params);
        }

        function getRequestToken(oauthSigner) {
            return $http.get(oauthSigner.signedUrl())
            .then(function(data) {
                return {
                    oauth_token: getURLParameter(data, "oauth_token"),
                    oauth_token_secret: getURLParameter(data, "oauth_token_secret"),
                    oauth_callback_confirmed: getURLParameter(data, "oauth_callback_confirmed")
                };
            });
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
                        oauth_verifier: getURLParameter(event.url, 'oauth_verifier')
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
            return $http.post(oauthSigner.signedUrl())
            .then(function(data) {
                return {
                    oauth_token: getURLParameter(data, "oauth_token"),
                    oauth_token_secret: getURLParameter(data, 'oauth_token_secret')
                };
            });
        }

        function getAuthorizedHttp(access_data) {
            var oauth_token = access_data.oauth_token;
            var oauth_token_secret = access_data.oauth_token_secret;
            var signer = getOAuthSigner({
                url : requestEndpoint,
                consumerKey : consumerKey,
                consumerSecret : consumerSecret,
                token : oauth_token,
                tokenSecret : oauth_token_secret
            });

            return oauth1AuthorizedHttp.create(signer);
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
                var oauthSigner = getOAuthSigner({
                    url : requestEndpoint,
                    consumerKey : consumerKey,
                    consumerSecret : consumerSecret,
                    callbackUrl : oauthCallback,
                    scopes : scopes
                });

                return getRequestToken(oauthSigner)
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
                    oauthPersistence.storeAccessToken(access_data);
                    return getAuthorizedHttp(access_data);
                });
            }
        };
    }];
})

.service('oauth1AuthorizedHttp', ['$http', 'oauth1Headers', function oauth1AuthorizedHttpService($http, oauth1Headers) {
    return {
        create: function(signer) {
            return function(config) {
                var headers = oauth1Headers.getHeaders(config.url, config.method || "GET", signer);
                var configWithHeaders = angular.extend({headers: headers}, config);
                return $http(configWithHeaders).then(
                    function(response){
                        response.data.authToken = signer.token;
                        return response;
                    });
            };
        }
    };
}])

.service('oauth1Headers', [function oauth1HeadersService() {
    return {
        getHeaders: function(url, method, signer) {
            var headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'};
            if (signer) {
                signer.method = method;
                signer.url = url;
                headers['Authorization'] = "OAuth " + signer.authorizationHeader();
            }
            return headers;
        },
        removeAuthorizationHeader: angular.noop
    };
}])

;

})(window, window.angular);
