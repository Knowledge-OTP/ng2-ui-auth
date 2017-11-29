var __extends = (this && this.__extends) || (function () {
    var extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
import { Injectable, Injector, NgModule } from '@angular/core';
import { Headers, Http, HttpModule, Request, RequestMethod, Response } from '@angular/http';
import { Observable as Observable$1 } from 'rxjs/Observable';
import 'rxjs/add/operator/switchMap';
import 'rxjs/add/operator/catch';
import 'rxjs/add/observable/interval';
import 'rxjs/add/observable/fromEvent';
import 'rxjs/add/observable/throw';
import 'rxjs/add/observable/empty';
import 'rxjs/add/observable/merge';
import 'rxjs/add/operator/take';
import 'rxjs/add/operator/map';
import 'rxjs/add/operator/takeWhile';
import 'rxjs/add/operator/delay';
import 'rxjs/add/operator/do';
import 'rxjs/add/observable/of';
/**
 * @abstract
 */
var CustomConfig = /** @class */ (function () {
    function CustomConfig() {
    }
    return CustomConfig;
}());
var ConfigService = /** @class */ (function () {
    /**
     * @param {?=} config
     */
    function ConfigService(config) {
        var _this = this;
        this.withCredentials = false;
        this.tokenRoot = null;
        this.baseUrl = '/';
        this.loginUrl = '/auth/login';
        this.signupUrl = '/auth/signup';
        this.unlinkUrl = '/auth/unlink/';
        this.refreshUrl = '/auth/refresh';
        this.tokenName = 'token';
        this.tokenSeparator = '_';
        this.tokenPrefix = 'ng2-ui-auth';
        this.authHeader = 'Authorization';
        this.authToken = 'Bearer';
        this.storageType = 'localStorage';
        this.defaultHeaders = null;
        this.autoRefreshToken = false;
        this.refreshBeforeExpiration = 600000; //10 minutes
        this.tryTokenRefreshIfUnauthorized = false;
        this.cordova = this.isCordovaApp();
        this.resolveToken = function (response) {
            var /** @type {?} */ tokenObj = response;
            if (response instanceof Response) {
                tokenObj = response.json();
            }
            var /** @type {?} */ accessToken = tokenObj &&
                (tokenObj['access_token'] || tokenObj['token'] || tokenObj['data']);
            if (!accessToken) {
                console.warn('No token found');
                return null;
            }
            if (typeof accessToken === 'string') {
                return accessToken;
            }
            if (typeof accessToken !== 'object') {
                console.warn('No token found');
                return null;
            }
            var /** @type {?} */ tokenRootData = _this.tokenRoot &&
                _this.tokenRoot.split('.').reduce(function (o, x) {
                    return o[x];
                }, accessToken);
            var /** @type {?} */ token = tokenRootData ? tokenRootData[_this.tokenName] : accessToken[_this.tokenName];
            if (token) {
                return token;
            }
            var /** @type {?} */ tokenPath = _this.tokenRoot ? _this.tokenRoot + '.' + _this.tokenName : _this.tokenName;
            console.warn('Expecting a token named "' + tokenPath);
            return null;
        };
        this.providers = {
            facebook: {
                name: 'facebook',
                url: '/auth/facebook',
                authorizationEndpoint: 'https://www.facebook.com/v2.5/dialog/oauth',
                redirectUri: this.getHttpHost('/'),
                requiredUrlParams: ['display', 'scope'],
                scope: ['email'],
                scopeDelimiter: ',',
                display: 'popup',
                oauthType: '2.0',
                popupOptions: { width: 580, height: 400 }
            },
            google: {
                name: 'google',
                url: '/auth/google',
                authorizationEndpoint: 'https://accounts.google.com/o/oauth2/auth',
                redirectUri: this.getHttpHost(),
                requiredUrlParams: ['scope'],
                optionalUrlParams: ['display', 'state', 'prompt', 'login_hint', 'access_type', 'include_granted_scopes', 'openid.realm', 'hd'],
                scope: ['profile', 'email'],
                scopePrefix: 'openid',
                scopeDelimiter: ' ',
                display: 'popup',
                oauthType: '2.0',
                popupOptions: { width: 452, height: 633 },
                state: function () { return encodeURIComponent(Math.random().toString(36).substr(2)); },
            },
            github: {
                name: 'github',
                url: '/auth/github',
                authorizationEndpoint: 'https://github.com/login/oauth/authorize',
                redirectUri: this.getHttpHost(),
                optionalUrlParams: ['scope'],
                scope: ['user:email'],
                scopeDelimiter: ' ',
                oauthType: '2.0',
                popupOptions: { width: 1020, height: 618 }
            },
            instagram: {
                name: 'instagram',
                url: '/auth/instagram',
                authorizationEndpoint: 'https://api.instagram.com/oauth/authorize',
                redirectUri: this.getHttpHost(),
                requiredUrlParams: ['scope'],
                scope: ['basic'],
                scopeDelimiter: '+',
                oauthType: '2.0'
            },
            linkedin: {
                name: 'linkedin',
                url: '/auth/linkedin',
                authorizationEndpoint: 'https://www.linkedin.com/uas/oauth2/authorization',
                redirectUri: this.getHttpHost(),
                requiredUrlParams: ['state'],
                scope: ['r_emailaddress'],
                scopeDelimiter: ' ',
                state: 'STATE',
                oauthType: '2.0',
                popupOptions: { width: 527, height: 582 }
            },
            twitter: {
                name: 'twitter',
                url: '/auth/twitter',
                authorizationEndpoint: 'https://api.twitter.com/oauth/authenticate',
                redirectUri: this.getHttpHost(),
                oauthType: '1.0',
                popupOptions: { width: 495, height: 645 }
            },
            twitch: {
                name: 'twitch',
                url: '/auth/twitch',
                authorizationEndpoint: 'https://api.twitch.tv/kraken/oauth2/authorize',
                redirectUri: this.getHttpHost(),
                requiredUrlParams: ['scope'],
                scope: ['user_read'],
                scopeDelimiter: ' ',
                display: 'popup',
                oauthType: '2.0',
                popupOptions: { width: 500, height: 560 }
            },
            live: {
                name: 'live',
                url: '/auth/live',
                authorizationEndpoint: 'https://login.live.com/oauth20_authorize.srf',
                redirectUri: this.getHttpHost(),
                requiredUrlParams: ['display', 'scope'],
                scope: ['wl.emails'],
                scopeDelimiter: ' ',
                display: 'popup',
                oauthType: '2.0',
                popupOptions: { width: 500, height: 560 }
            },
            yahoo: {
                name: 'yahoo',
                url: '/auth/yahoo',
                authorizationEndpoint: 'https://api.login.yahoo.com/oauth2/request_auth',
                redirectUri: this.getHttpHost(),
                scope: [],
                scopeDelimiter: ',',
                oauthType: '2.0',
                popupOptions: { width: 559, height: 519 }
            },
            bitbucket: {
                name: 'bitbucket',
                url: '/auth/bitbucket',
                authorizationEndpoint: 'https://bitbucket.org/site/oauth2/authorize',
                redirectUri: this.getHttpHost('/'),
                requiredUrlParams: ['scope'],
                scope: ['email'],
                scopeDelimiter: ',',
                oauthType: '2.0',
                popupOptions: { width: 1028, height: 529 }
            },
            spotify: {
                name: 'spotify',
                url: '/auth/spotify',
                authorizationEndpoint: 'https://accounts.spotify.com/authorize',
                redirectUri: this.getHttpHost(),
                optionalUrlParams: ['state'],
                requiredUrlParams: ['scope'],
                scope: ['user-read-email'],
                scopePrefix: '',
                scopeDelimiter: ',',
                oauthType: '2.0',
                popupOptions: { width: 500, height: 530 },
                state: function () { return encodeURIComponent(Math.random().toString(36).substr(2)); }
            }
        };
        Object.keys(config).forEach(function (key) {
            if (typeof config[key] === "undefined") {
                return;
            }
            if (key !== 'providers') {
                _this[key] = config[key];
            }
            else {
                Object.keys(config[key]).map(function (provider) {
                    _this.providers[provider] = Object.assign(_this.providers[provider] || {}, config.providers[provider]);
                });
            }
        });
    }
    /**
     * @param {?=} path
     * @return {?}
     */
    ConfigService.prototype.getHttpHost = function (path) {
        if (path === void 0) { path = ''; }
        return window.location.origin + path;
    };
    /**
     * @return {?}
     */
    ConfigService.prototype.isCordovaApp = function () {
        return !!window['cordova'];
    };
    return ConfigService;
}());
ConfigService.decorators = [
    { type: Injectable },
];
/**
 * @nocollapse
 */
ConfigService.ctorParameters = function () { return [
    { type: CustomConfig, },
]; };
/**
 * @abstract
 */
var StorageService = /** @class */ (function () {
    function StorageService() {
    }
    /**
     * @abstract
     * @param {?} key
     * @return {?}
     */
    StorageService.prototype.get = function (key) { };
    /**
     * @abstract
     * @param {?} key
     * @param {?} value
     * @param {?} date
     * @return {?}
     */
    StorageService.prototype.set = function (key, value, date) { };
    /**
     * @abstract
     * @param {?} key
     * @return {?}
     */
    StorageService.prototype.remove = function (key) { };
    return StorageService;
}());
/**
 * Created by Ron on 17/12/2015.
 */
var BrowserStorageService = /** @class */ (function (_super) {
    __extends(BrowserStorageService, _super);
    /**
     * @param {?} config
     */
    function BrowserStorageService(config) {
        var _this = _super.call(this) || this;
        _this.config = config;
        _this.store = {};
        _this.isStorageAvailable = _this.checkIsStorageAvailable(config);
        if (!_this.isStorageAvailable) {
            console.warn(config.storageType + ' is not available.');
        }
        return _this;
    }
    /**
     * @param {?} key
     * @return {?}
     */
    BrowserStorageService.prototype.get = function (key) {
        return this.isStorageAvailable
            ? this.config.storageType === 'cookie' || this.config.storageType === 'sessionCookie'
                ? this.getCookie(key)
                : window[this.config.storageType].getItem(key)
            : this.store[key];
    };
    /**
     * @param {?} key
     * @param {?} value
     * @param {?} date
     * @return {?}
     */
    BrowserStorageService.prototype.set = function (key, value, date) {
        this.isStorageAvailable
            ? this.config.storageType === 'cookie' || this.config.storageType === 'sessionCookie'
                ? this.setCookie(key, value, this.config.storageType === 'cookie' ? date : '')
                : window[this.config.storageType].setItem(key, value)
            : this.store[key] = value;
    };
    /**
     * @param {?} key
     * @return {?}
     */
    BrowserStorageService.prototype.remove = function (key) {
        this.isStorageAvailable
            ? this.config.storageType === 'cookie' || this.config.storageType === 'sessionCookie'
                ? this.removeCookie(key)
                : window[this.config.storageType].removeItem(key)
            : delete this.store[key];
    };
    /**
     * @param {?} config
     * @return {?}
     */
    BrowserStorageService.prototype.checkIsStorageAvailable = function (config) {
        if (config.storageType === 'cookie' || config.storageType === 'sessionCookie') {
            return this.isCookieStorageAvailable();
        }
        try {
            var /** @type {?} */ supported = window && config.storageType in window && window[config.storageType] !== null;
            if (supported) {
                var /** @type {?} */ key = Math.random().toString(36).substring(7);
                window[this.config.storageType].setItem(key, '');
                window[this.config.storageType].removeItem(key);
            }
            return supported;
        }
        catch (e) {
            return false;
        }
    };
    /**
     * @return {?}
     */
    BrowserStorageService.prototype.isCookieStorageAvailable = function () {
        try {
            var /** @type {?} */ supported = document && 'cookie' in document;
            if (supported) {
                var /** @type {?} */ key = Math.random().toString(36).substring(7);
                this.setCookie(key, 'test', new Date(Date.now() + 60 * 1000).toUTCString());
                var /** @type {?} */ value = this.getCookie(key);
                this.removeCookie(key);
                return value === 'test';
            }
            return false;
        }
        catch (e) {
            return false;
        }
    };
    /**
     * @param {?} key
     * @param {?} value
     * @param {?=} expires
     * @param {?=} path
     * @return {?}
     */
    BrowserStorageService.prototype.setCookie = function (key, value, expires, path) {
        if (expires === void 0) { expires = ''; }
        if (path === void 0) { path = '/'; }
        document.cookie = key + "=" + value + (expires ? "; expires=" + expires : '') + "; path=" + path;
    };
    /**
     * @param {?} key
     * @param {?=} path
     * @return {?}
     */
    BrowserStorageService.prototype.removeCookie = function (key, path) {
        if (path === void 0) { path = '/'; }
        this.setCookie(key, '', new Date(0).toUTCString(), path);
    };
    /**
     * @param {?} key
     * @return {?}
     */
    BrowserStorageService.prototype.getCookie = function (key) {
        return document.cookie.replace(new RegExp("(?:(?:^|.*;\\s*)" + key + "\\s*\\=\\s*([^;]*).*$)|^.*$"), '$1');
    };
    return BrowserStorageService;
}(StorageService));
BrowserStorageService.decorators = [
    { type: Injectable },
];
/**
 * @nocollapse
 */
BrowserStorageService.ctorParameters = function () { return [
    { type: ConfigService, },
]; };
/**
 * Created by Ron on 17/12/2015.
 */
/**
 * Created by Ron on 17/12/2015.
 */
var SharedService = /** @class */ (function () {
    /**
     * @param {?} storage
     * @param {?} config
     */
    function SharedService(storage, config) {
        this.storage = storage;
        this.config = config;
        this.tokenName = this.config.tokenPrefix ? [this.config.tokenPrefix, this.config.tokenName].join(this.config.tokenSeparator) : this.config.tokenName;
    }
    /**
     * @return {?}
     */
    SharedService.prototype.getToken = function () {
        return this.storage.get(this.tokenName);
    };
    /**
     * @param {?=} token
     * @return {?}
     */
    SharedService.prototype.getPayload = function (token) {
        if (token === void 0) { token = this.getToken(); }
        if (token && token.split('.').length === 3) {
            try {
                var /** @type {?} */ base64Url = token.split('.')[1];
                var /** @type {?} */ base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
                return JSON.parse(decodeURIComponent(encodeURIComponent(window.atob(base64))));
            }
            catch (e) {
                return undefined;
            }
        }
    };
    /**
     * @param {?} response
     * @return {?}
     */
    SharedService.prototype.setToken = function (response) {
        if (!response) {
            console.warn('Can\'t set token without passing a value');
            return;
        }
        var /** @type {?} */ token;
        if (typeof response === 'string') {
            token = response;
        }
        else {
            token = this.config.resolveToken(response);
        }
        if (token) {
            var /** @type {?} */ expDate = this.getExpirationDate(token);
            this.storage.set(this.tokenName, token, expDate ? expDate.toUTCString() : '');
        }
    };
    /**
     * @return {?}
     */
    SharedService.prototype.removeToken = function () {
        this.storage.remove(this.tokenName);
    };
    /**
     * @param {?=} token
     * @return {?}
     */
    SharedService.prototype.isAuthenticated = function (token) {
        if (token === void 0) { token = this.getToken(); }
        // a token is present
        if (token) {
            // token with a valid JWT format XXX.YYY.ZZZ
            if (token.split('.').length === 3) {
                // could be a valid JWT or an access token with the same format
                try {
                    var /** @type {?} */ base64Url = token.split('.')[1];
                    var /** @type {?} */ base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
                    var /** @type {?} */ exp = JSON.parse(window.atob(base64)).exp;
                    // jwt with an optional expiration claims
                    if (exp) {
                        var /** @type {?} */ isExpired = Math.round(new Date().getTime() / 1000) >= exp;
                        if (isExpired) {
                            // fail: Expired token
                            this.storage.remove(this.tokenName);
                            return false;
                        }
                        else {
                            // pass: Non-expired token
                            return true;
                        }
                    }
                }
                catch (e) {
                    // pass: Non-JWT token that looks like JWT
                    return true;
                }
            }
            // pass: All other tokens
            return true;
        }
        // lail: No token at all
        return false;
    };
    /**
     * @param {?=} token
     * @return {?}
     */
    SharedService.prototype.getExpirationDate = function (token) {
        if (token === void 0) { token = this.getToken(); }
        var /** @type {?} */ payload = this.getPayload(token);
        if (payload && payload.exp && Math.round(new Date().getTime() / 1000) < payload.exp) {
            var /** @type {?} */ date = new Date(0);
            date.setUTCSeconds(payload.exp);
            return date;
        }
        return null;
    };
    /**
     * @return {?}
     */
    SharedService.prototype.logout = function () {
        var _this = this;
        return Observable$1.create(function (observer) {
            _this.storage.remove(_this.tokenName);
            observer.next();
            observer.complete();
        });
    };
    /**
     * @param {?} type
     * @return {?}
     */
    SharedService.prototype.setStorageType = function (type) {
        this.config.storageType = type;
    };
    return SharedService;
}());
SharedService.decorators = [
    { type: Injectable },
];
/**
 * @nocollapse
 */
SharedService.ctorParameters = function () { return [
    { type: StorageService, },
    { type: ConfigService, },
]; };
var JwtHttp = /** @class */ (function () {
    /**
     * @param {?} _http
     * @param {?} _shared
     * @param {?} _config
     */
    function JwtHttp(_http, _shared, _config) {
        this._http = _http;
        this._shared = _shared;
        this._config = _config;
    }
    /**
     * @param {?} url
     * @param {?=} options
     * @return {?}
     */
    JwtHttp.prototype.request = function (url, options) {
        var _this = this;
        //if the token is expired the "getExpirationDate" function returns null
        var /** @type {?} */ exp = this._shared.getExpirationDate();
        if (this._shared.getToken() &&
            (!exp || exp.getTime() + this._config.refreshBeforeExpiration > Date.now()) &&
            (options.autoRefreshToken ||
                typeof options.autoRefreshToken === 'undefined' && this._config.autoRefreshToken)) {
            return this.refreshToken()
                .switchMap(function () { return _this.actualRequest(url, options); });
        }
        if (this._config.tryTokenRefreshIfUnauthorized) {
            return this.actualRequest(url, options)
                .catch(function (response) {
                if (response.status === 401) {
                    return _this.refreshToken()
                        .switchMap(function () { return _this.actualRequest(url, options); });
                }
                throw response;
            });
        }
        return this.actualRequest(url, options);
    };
    /**
     * @param {?} url
     * @param {?=} options
     * @return {?}
     */
    JwtHttp.prototype.get = function (url, options) {
        options = options || {};
        options.method = RequestMethod.Get;
        return this.request(url, options);
    };
    /**
     * @param {?} url
     * @param {?} body
     * @param {?=} options
     * @return {?}
     */
    JwtHttp.prototype.post = function (url, body, options) {
        options = options || {};
        options.method = RequestMethod.Post;
        options.body = body;
        return this.request(url, options);
    };
    /**
     * @param {?} url
     * @param {?} body
     * @param {?=} options
     * @return {?}
     */
    JwtHttp.prototype.put = function (url, body, options) {
        options = options || {};
        options.method = RequestMethod.Put;
        options.body = body;
        return this.request(url, options);
    };
    /**
     * @param {?} url
     * @param {?=} options
     * @return {?}
     */
    JwtHttp.prototype.delete = function (url, options) {
        options = options || {};
        options.method = RequestMethod.Delete;
        return this.request(url, options);
    };
    /**
     * @param {?} url
     * @param {?} body
     * @param {?=} options
     * @return {?}
     */
    JwtHttp.prototype.patch = function (url, body, options) {
        options = options || {};
        options.method = RequestMethod.Patch;
        options.body = body;
        return this.request(url, options);
    };
    /**
     * @param {?} url
     * @param {?=} options
     * @return {?}
     */
    JwtHttp.prototype.head = function (url, options) {
        options = options || {};
        options.method = RequestMethod.Head;
        return this.request(url, options);
    };
    /**
     * @return {?}
     */
    JwtHttp.prototype.refreshToken = function () {
        var _this = this;
        var /** @type {?} */ authHeader = new Headers();
        authHeader.append(this._config.authHeader, (this._config.authToken + ' ' + this._shared.getToken()));
        return this._http
            .get(this._config.refreshUrl, {
            headers: authHeader
        })
            .do(function (res) { return _this._shared.setToken(res); });
    };
    /**
     * @param {?} url
     * @param {?=} options
     * @return {?}
     */
    JwtHttp.prototype.actualRequest = function (url, options) {
        if (url instanceof Request) {
            url.headers = url.headers || new Headers();
            this.setHeaders(url);
        }
        else {
            options = options || {};
            this.setHeaders(options);
        }
        return this._http.request(url, options);
    };
    /**
     * @param {?} obj
     * @return {?}
     */
    JwtHttp.prototype.setHeaders = function (obj) {
        var _this = this;
        obj.headers = obj.headers || new Headers();
        if (this._config.defaultHeaders) {
            Object.keys(this._config.defaultHeaders).forEach(function (defaultHeader) {
                if (!obj.headers.has(defaultHeader)) {
                    obj.headers.set(defaultHeader, _this._config.defaultHeaders[defaultHeader]);
                }
            });
        }
        if (this._shared.isAuthenticated()) {
            obj.headers.set(this._config.authHeader, this._config.authToken + ' ' + this._shared.getToken());
        }
    };
    return JwtHttp;
}());
JwtHttp.decorators = [
    { type: Injectable },
];
/**
 * @nocollapse
 */
JwtHttp.ctorParameters = function () { return [
    { type: Http, },
    { type: SharedService, },
    { type: ConfigService, },
]; };
/**
 * Created by Ron on 17/12/2015.
 * @param {?} target
 * @param {...?} src
 * @return {?}
 */
function assign(target) {
    var src = [];
    for (var _i = 1; _i < arguments.length; _i++) {
        src[_i - 1] = arguments[_i];
    }
    if (target == null) {
        throw new TypeError('Cannot convert undefined or null to object');
    }
    target = Object(target);
    for (var /** @type {?} */ index = 1; index < arguments.length; index++) {
        var /** @type {?} */ source = arguments[index];
        if (source != null) {
            for (var /** @type {?} */ key in source) {
                if (Object.prototype.hasOwnProperty.call(source, key)) {
                    target[key] = source[key];
                }
            }
        }
    }
    return target;
}
/**
 * @param {?} baseUrl
 * @param {?} url
 * @return {?}
 */
function joinUrl(baseUrl, url) {
    if (/^(?:[a-z]+:)?\/\//i.test(url)) {
        return url;
    }
    var /** @type {?} */ joined = [baseUrl, url].join('/');
    var /** @type {?} */ normalize = function (str) {
        return str
            .replace(/[\/]+/g, '/')
            .replace(/\/\?/g, '?')
            .replace(/\/\#/g, '#')
            .replace(/\:\//g, '://');
    };
    return normalize(joined);
}
/**
 * @param {?} obj1
 * @param {?} obj2
 * @return {?}
 */
function merge$1(obj1, obj2) {
    var /** @type {?} */ result = {};
    for (var /** @type {?} */ i in obj1) {
        if (obj1.hasOwnProperty(i)) {
            if ((i in obj2) && (typeof obj1[i] === 'object') && (i !== null)) {
                result[i] = merge$1(obj1[i], obj2[i]);
            }
            else {
                result[i] = obj1[i];
            }
        }
    }
    for (i in obj2) {
        if (obj2.hasOwnProperty(i)) {
            if (i in result) {
                continue;
            }
            result[i] = obj2[i];
        }
    }
    return result;
}
/**
 * @param {?} name
 * @return {?}
 */
function camelCase(name) {
    return name.replace(/([\:\-\_]+(.))/g, function (_, separator, letter, offset) {
        return offset ? letter.toUpperCase() : letter;
    });
}
/**
 * Created by Ron on 17/12/2015.
 */
var PopupService = /** @class */ (function () {
    /**
     * @param {?} config
     */
    function PopupService(config) {
        this.config = config;
        this.url = '';
        this.popupWindow = null;
    }
    /**
     * @param {?} url
     * @param {?} name
     * @param {?} options
     * @return {?}
     */
    PopupService.prototype.open = function (url, name, options) {
        this.url = url;
        var /** @type {?} */ stringifiedOptions = this.stringifyOptions(this.prepareOptions(options));
        var /** @type {?} */ UA = window.navigator.userAgent;
        var /** @type {?} */ windowName = (this.config.cordova || UA.indexOf('CriOS') > -1) ? '_blank' : name;
        this.popupWindow = window.open(url, windowName, stringifiedOptions);
        window['popup'] = this.popupWindow;
        if (this.popupWindow && this.popupWindow.focus) {
            this.popupWindow.focus();
        }
        return this;
    };
    /**
     * @param {?} redirectUri
     * @return {?}
     */
    PopupService.prototype.eventListener = function (redirectUri) {
        var _this = this;
        return Observable$1
            .merge(Observable$1.fromEvent(this.popupWindow, 'loadstart')
            .switchMap(function (event) {
            if (!_this.popupWindow || _this.popupWindow.closed) {
                return Observable$1.throw(new Error('Authentication Canceled'));
            }
            if (event.url.indexOf(redirectUri) !== 0) {
                return Observable$1.empty();
            }
            var /** @type {?} */ parser = document.createElement('a');
            parser.href = event.url;
            if (parser.search || parser.hash) {
                var /** @type {?} */ queryParams = parser.search.substring(1).replace(/\/$/, '');
                var /** @type {?} */ hashParams = parser.hash.substring(1).replace(/\/$/, '');
                var /** @type {?} */ hash = _this.parseQueryString(hashParams);
                var /** @type {?} */ qs = _this.parseQueryString(queryParams);
                var /** @type {?} */ allParams = assign({}, qs, hash);
                _this.popupWindow.close();
                if (allParams.error) {
                    throw allParams.error;
                }
                else {
                    return Observable$1.of(allParams);
                }
            }
            return Observable$1.empty();
        }), Observable$1.fromEvent(this.popupWindow, 'exit').delay(100).map(function () { throw new Error('Authentication Canceled'); })).take(1);
    };
    /**
     * @return {?}
     */
    PopupService.prototype.pollPopup = function () {
        var _this = this;
        return Observable$1
            .interval(50)
            .switchMap(function () {
            if (!_this.popupWindow || _this.popupWindow.closed) {
                return Observable$1.throw(new Error('Authentication Canceled'));
            }
            var /** @type {?} */ documentOrigin = document.location.host;
            var /** @type {?} */ popupWindowOrigin = '';
            try {
                popupWindowOrigin = _this.popupWindow.location.host;
            }
            catch (error) {
                // ignore DOMException: Blocked a frame with origin from accessing a cross-origin frame.
                //error instanceof DOMException && error.name === 'SecurityError'
            }
            if (popupWindowOrigin === documentOrigin && (_this.popupWindow.location.search || _this.popupWindow.location.hash)) {
                var /** @type {?} */ queryParams = _this.popupWindow.location.search.substring(1).replace(/\/$/, '');
                var /** @type {?} */ hashParams = _this.popupWindow.location.hash.substring(1).replace(/[\/$]/, '');
                var /** @type {?} */ hash = _this.parseQueryString(hashParams);
                var /** @type {?} */ qs = _this.parseQueryString(queryParams);
                _this.popupWindow.close();
                var /** @type {?} */ allParams = assign({}, qs, hash);
                if (allParams.error) {
                    throw allParams.error;
                }
                else {
                    return Observable$1.of(allParams);
                }
            }
            return Observable$1.empty();
        })
            .take(1);
    };
    /**
     * @param {?} options
     * @return {?}
     */
    PopupService.prototype.prepareOptions = function (options) {
        options = options || {};
        var /** @type {?} */ width = options.width || 500;
        var /** @type {?} */ height = options.height || 500;
        return assign({
            width: width,
            height: height,
            left: window.screenX + ((window.outerWidth - width) / 2),
            top: window.screenY + ((window.outerHeight - height) / 2.5),
            toolbar: options.visibleToolbar ? 'yes' : 'no'
        }, options);
    };
    /**
     * @param {?} options
     * @return {?}
     */
    PopupService.prototype.stringifyOptions = function (options) {
        return Object.keys(options).map(function (key) {
            return key + '=' + options[key];
        }).join(',');
    };
    /**
     * @param {?} joinedKeyValue
     * @return {?}
     */
    PopupService.prototype.parseQueryString = function (joinedKeyValue) {
        var /** @type {?} */ key, /** @type {?} */ value;
        return joinedKeyValue.split('&').reduce(function (obj, keyValue) {
            if (keyValue) {
                value = keyValue.split('=');
                key = decodeURIComponent(value[0]);
                obj[key] = typeof value[1] !== 'undefined' ? decodeURIComponent(value[1]) : true;
            }
            return obj;
        }, {});
    };
    return PopupService;
}());
PopupService.decorators = [
    { type: Injectable },
];
/**
 * @nocollapse
 */
PopupService.ctorParameters = function () { return [
    { type: ConfigService, },
]; };
/**
 * Created by Ron on 17/12/2015.
 */
var Oauth1Service = /** @class */ (function () {
    /**
     * @param {?} http
     * @param {?} popup
     * @param {?} config
     */
    function Oauth1Service(http$$1, popup, config) {
        this.http = http$$1;
        this.popup = popup;
        this.config = config;
    }
    /**
     * @param {?=} options
     * @param {?=} userData
     * @return {?}
     */
    Oauth1Service.prototype.open = function (options, userData) {
        var _this = this;
        this.defaults = assign({}, Oauth1Service.base, options);
        var /** @type {?} */ popupWindow;
        var /** @type {?} */ serverUrl = this.config.baseUrl ? joinUrl(this.config.baseUrl, this.defaults.url) : this.defaults.url;
        if (!this.config.cordova) {
            popupWindow = this.popup.open('', this.defaults.name, this.defaults.popupOptions /*, this.defaults.redirectUri*/);
        }
        return this.http.post(serverUrl, JSON.stringify(this.defaults))
            .switchMap(function (response) {
            if (_this.config.cordova) {
                popupWindow = _this.popup.open([_this.defaults.authorizationEndpoint, _this.buildQueryString(response.json())].join('?'), _this.defaults.name, _this.defaults.popupOptions);
            }
            else {
                popupWindow.popupWindow.location =
                    [_this.defaults.authorizationEndpoint, _this.buildQueryString(response.json())].join('?');
            }
            return _this.config.cordova ? popupWindow.eventListener(_this.defaults.redirectUri) : popupWindow.pollPopup();
        })
            .switchMap(function (response) {
            var /** @type {?} */ exchangeForToken = options.exchangeForToken;
            if (typeof exchangeForToken !== 'function') {
                exchangeForToken = _this.exchangeForToken.bind(_this);
            }
            return exchangeForToken(response, userData);
        });
    };
    /**
     * @param {?} oauthData
     * @param {?=} userData
     * @return {?}
     */
    Oauth1Service.prototype.exchangeForToken = function (oauthData, userData) {
        var /** @type {?} */ data = assign({}, this.defaults, oauthData, userData);
        var /** @type {?} */ exchangeForTokenUrl = this.config.baseUrl ? joinUrl(this.config.baseUrl, this.defaults.url) : this.defaults.url;
        return this.defaults.method
            ? this.http.request(exchangeForTokenUrl, {
                body: JSON.stringify(data),
                withCredentials: this.config.withCredentials,
                method: this.defaults.method
            })
            : this.http.post(exchangeForTokenUrl, data, { withCredentials: this.config.withCredentials });
    };
    /**
     * @param {?} obj
     * @return {?}
     */
    Oauth1Service.prototype.buildQueryString = function (obj) {
        return Object.keys(obj).map(function (key) {
            return encodeURIComponent(key) + '=' + encodeURIComponent(obj[key]);
        }).join('&');
    };
    return Oauth1Service;
}());
Oauth1Service.base = {
    url: null,
    name: null,
    popupOptions: null,
    redirectUri: null,
    authorizationEndpoint: null
};
Oauth1Service.decorators = [
    { type: Injectable },
];
/**
 * @nocollapse
 */
Oauth1Service.ctorParameters = function () { return [
    { type: JwtHttp, },
    { type: PopupService, },
    { type: ConfigService, },
]; };
/**
 * Created by Ron on 17/12/2015.
 */
var OauthService = /** @class */ (function () {
    /**
     * @param {?} http
     * @param {?} injector
     * @param {?} shared
     * @param {?} config
     */
    function OauthService(http$$1, injector, shared, config) {
        this.http = http$$1;
        this.injector = injector;
        this.shared = shared;
        this.config = config;
    }
    /**
     * @param {?} name
     * @param {?=} userData
     * @param {?=} oauth
     * @return {?}
     */
    OauthService.prototype.authenticate = function (name, userData, oauth) {
        var _this = this;
        // var injector = Injector.resolveAndCreate([Oauth1, Oauth2]);
        var /** @type {?} */ provider = this.config.providers[name].oauthType === '1.0' ? this.injector.get(Oauth1Service) : oauth;
        return provider.open(this.config.providers[name], userData || {})
            .do(function (response) {
            // this is for a scenario when someone wishes to opt out from
            // satellizer's magic by doing authorization code exchange and
            // saving a token manually.
            if (_this.config.providers[name].url) {
                _this.shared.setToken(response);
            }
        });
    };
    /**
     * @param {?} provider
     * @param {?} opts
     * @return {?}
     */
    OauthService.prototype.unlink = function (provider, opts) {
        opts = opts || {};
        var /** @type {?} */ url = opts.url ? opts.url : joinUrl(this.config.baseUrl, this.config.unlinkUrl);
        opts.body = JSON.stringify({ provider: provider }) || opts.body;
        opts.method = opts.method || 'POST';
        return this.http.request(url, opts);
    };
    return OauthService;
}());
OauthService.decorators = [
    { type: Injectable },
];
/**
 * @nocollapse
 */
OauthService.ctorParameters = function () { return [
    { type: JwtHttp, },
    { type: Injector, },
    { type: SharedService, },
    { type: ConfigService, },
]; };
/**
 * Created by Ron on 17/12/2015.
 */
var Oauth2Service = /** @class */ (function () {
    /**
     * @param {?} http
     * @param {?} popup
     * @param {?} storage
     * @param {?} config
     */
    function Oauth2Service(http$$1, popup, storage, config) {
        this.http = http$$1;
        this.popup = popup;
        this.storage = storage;
        this.config = config;
    }
    /**
     * @param {?} options
     * @param {?=} userData
     * @return {?}
     */
    Oauth2Service.prototype.open = function (options, userData) {
        var _this = this;
        this.defaults = merge$1(options, Oauth2Service.base);
        var /** @type {?} */ url;
        var /** @type {?} */ openPopup;
        var /** @type {?} */ stateName = this.defaults.name + '_state';
        var /** @type {?} */ state = this.defaults.state;
        var /** @type {?} */ exp = new Date(Date.now() + 60 * 60 * 1000).toUTCString();
        if (typeof state === 'string') {
            this.storage.set(stateName, state, exp);
        }
        else if (typeof state === 'function') {
            this.storage.set(stateName, state(), exp);
        }
        url = [this.defaults.authorizationEndpoint, this.buildQueryString()].join('?');
        if (this.config.cordova) {
            openPopup = this.popup
                .open(url, this.defaults.name, this.defaults.popupOptions /*, this.defaults.redirectUri*/)
                .eventListener(this.defaults.redirectUri);
        }
        else {
            openPopup = this.popup
                .open(url, this.defaults.name, this.defaults.popupOptions /*, this.defaults.redirectUri*/)
                .pollPopup();
        }
        return openPopup
            .switchMap(function (oauthData) {
            // when no server URL provided, return popup params as-is.
            // this is for a scenario when someone wishes to opt out from
            // satellizer's magic by doing authorization code exchange and
            // saving a token manually.
            if (_this.defaults.responseType === 'token' || !_this.defaults.url) {
                return Observable$1.of(oauthData);
            }
            if (oauthData.state && oauthData.state !== _this.storage.get(stateName)) {
                throw 'OAuth "state" mismatch';
            }
            var /** @type {?} */ exchangeForToken = options.exchangeForToken;
            if (typeof exchangeForToken !== 'function') {
                exchangeForToken = _this.exchangeForToken.bind(_this);
            }
            return exchangeForToken(oauthData, userData);
        });
    };
    /**
     * @param {?} oauthData
     * @param {?=} userData
     * @return {?}
     */
    Oauth2Service.prototype.exchangeForToken = function (oauthData, userData) {
        var /** @type {?} */ data = assign({}, this.defaults, oauthData, userData);
        var /** @type {?} */ exchangeForTokenUrl = this.config.baseUrl ? joinUrl(this.config.baseUrl, this.defaults.url) : this.defaults.url;
        return this.defaults.method
            ? this.http.request(exchangeForTokenUrl, {
                body: JSON.stringify(data),
                withCredentials: this.config.withCredentials,
                method: this.defaults.method
            })
            : this.http.post(exchangeForTokenUrl, JSON.stringify(data), { withCredentials: this.config.withCredentials });
    };
    /**
     * @return {?}
     */
    Oauth2Service.prototype.buildQueryString = function () {
        var _this = this;
        var /** @type {?} */ keyValuePairs = [];
        var /** @type {?} */ urlParams = ['defaultUrlParams', 'requiredUrlParams', 'optionalUrlParams'];
        urlParams.forEach(function (params) {
            if (_this.defaults[params]) {
                ((_this.defaults[params])).forEach(function (paramName) {
                    var /** @type {?} */ camelizedName = camelCase(paramName);
                    var /** @type {?} */ paramValue = typeof _this.defaults[paramName] === 'function' ?
                        _this.defaults[paramName]() :
                        _this.defaults[camelizedName];
                    if (paramName === 'state') {
                        var /** @type {?} */ stateName = _this.defaults.name + '_state';
                        paramValue = encodeURIComponent(_this.storage.get(stateName));
                    }
                    if (paramName === 'scope' && Array.isArray(paramValue)) {
                        paramValue = paramValue.join(_this.defaults.scopeDelimiter);
                        if (_this.defaults.scopePrefix) {
                            paramValue = [_this.defaults.scopePrefix, paramValue].join(_this.defaults.scopeDelimiter);
                        }
                    }
                    if (params !== 'optionalUrlParams' || typeof paramValue !== 'undefined') {
                        keyValuePairs.push([paramName, paramValue]);
                    }
                });
            }
        });
        return keyValuePairs.map(function (pair) {
            return pair.join('=');
        }).join('&');
    };
    return Oauth2Service;
}());
Oauth2Service.base = {
    defaultUrlParams: ['response_type', 'client_id', 'redirect_uri'],
    responseType: 'code',
    responseParams: {
        code: 'code',
        clientId: 'clientId',
        redirectUri: 'redirectUri'
    }
};
Oauth2Service.decorators = [
    { type: Injectable },
];
/**
 * @nocollapse
 */
Oauth2Service.ctorParameters = function () { return [
    { type: JwtHttp, },
    { type: PopupService, },
    { type: StorageService, },
    { type: ConfigService, },
]; };
/**
 * Created by Ron on 17/12/2015.
 * @param {?} user
 * @param {?=} userOpts
 * @return {?}
 */
function getFullOpts(user, userOpts) {
    var /** @type {?} */ opts = userOpts || {};
    if (user) {
        opts.body = typeof user === 'string' ? user : JSON.stringify(user);
    }
    opts.method = opts.method || 'POST';
    return opts;
}
var LocalService = /** @class */ (function () {
    /**
     * @param {?} http
     * @param {?} shared
     * @param {?} config
     */
    function LocalService(http$$1, shared, config) {
        this.http = http$$1;
        this.shared = shared;
        this.config = config;
    }
    /**
     * @param {?} user
     * @param {?=} opts
     * @return {?}
     */
    LocalService.prototype.login = function (user, opts) {
        var _this = this;
        var /** @type {?} */ fullOpts = getFullOpts(user, opts);
        var /** @type {?} */ url = fullOpts.url ? fullOpts.url : joinUrl(this.config.baseUrl, this.config.loginUrl);
        return this.http.request(url, fullOpts)
            .do(function (response) { return _this.shared.setToken(response); });
    };
    /**
     * @param {?} user
     * @param {?=} opts
     * @return {?}
     */
    LocalService.prototype.signup = function (user, opts) {
        var /** @type {?} */ fullOpts = getFullOpts(user, opts);
        var /** @type {?} */ url = fullOpts.url ? fullOpts.url : joinUrl(this.config.baseUrl, this.config.signupUrl);
        return this.http.request(url, getFullOpts(user, fullOpts));
    };
    return LocalService;
}());
LocalService.decorators = [
    { type: Injectable },
];
/**
 * @nocollapse
 */
LocalService.ctorParameters = function () { return [
    { type: JwtHttp, },
    { type: SharedService, },
    { type: ConfigService, },
]; };
/**
 * Created by Ron on 17/12/2015.
 */
var AuthService = /** @class */ (function () {
    /**
     * @param {?} shared
     * @param {?} local
     * @param {?} oauth
     */
    function AuthService(shared, local, oauth) {
        this.shared = shared;
        this.local = local;
        this.oauth = oauth;
    }
    /**
     * @param {?} user
     * @param {?=} opts
     * @return {?}
     */
    AuthService.prototype.login = function (user, opts) {
        return this.local.login(user, opts);
    };
    /**
     * @param {?} user
     * @param {?=} opts
     * @return {?}
     */
    AuthService.prototype.signup = function (user, opts) {
        return this.local.signup(user, opts);
    };
    /**
     * @return {?}
     */
    AuthService.prototype.logout = function () {
        return this.shared.logout();
    };
    /**
     * @param {?} name
     * @param {?=} userData
     * @param {?=} oauth
     * @return {?}
     */
    AuthService.prototype.authenticate = function (name, userData, oauth) {
        return this.oauth.authenticate(name, userData, oauth);
    };
    /**
     * @param {?} name
     * @param {?=} userData
     * @return {?}
     */
    AuthService.prototype.link = function (name, userData) {
        return this.oauth.authenticate(name, userData);
    };
    /**
     * @param {?} provider
     * @param {?} opts
     * @return {?}
     */
    AuthService.prototype.unlink = function (provider, opts) {
        return this.oauth.unlink(provider, opts);
    };
    /**
     * @return {?}
     */
    AuthService.prototype.isAuthenticated = function () {
        return this.shared.isAuthenticated();
    };
    /**
     * @return {?}
     */
    AuthService.prototype.getToken = function () {
        return this.shared.getToken();
    };
    /**
     * @param {?} token
     * @return {?}
     */
    AuthService.prototype.setToken = function (token) {
        this.shared.setToken(token);
    };
    /**
     * @return {?}
     */
    AuthService.prototype.removeToken = function () {
        this.shared.removeToken();
    };
    /**
     * @return {?}
     */
    AuthService.prototype.getPayload = function () {
        return this.shared.getPayload();
    };
    /**
     * @param {?} type
     * @return {?}
     */
    AuthService.prototype.setStorageType = function (type) {
        this.shared.setStorageType(type);
    };
    /**
     * @return {?}
     */
    AuthService.prototype.getExpirationDate = function () {
        return this.shared.getExpirationDate();
    };
    return AuthService;
}());
AuthService.decorators = [
    { type: Injectable },
];
/**
 * @nocollapse
 */
AuthService.ctorParameters = function () { return [
    { type: SharedService, },
    { type: LocalService, },
    { type: OauthService, },
]; };
/**
 * Created by Ron on 25/12/2015.
 */
var Ng2UiAuthModule = /** @class */ (function () {
    function Ng2UiAuthModule() {
    }
    /**
     * @param {?} config
     * @param {?} httpProvider
     * @return {?}
     */
    Ng2UiAuthModule.forRootWithCustomHttp = function (config, httpProvider) {
        return {
            ngModule: Ng2UiAuthModule,
            providers: [
                { provide: CustomConfig, useClass: config },
                { provide: ConfigService, useClass: ConfigService, deps: [CustomConfig] },
                { provide: StorageService, useClass: BrowserStorageService, deps: [ConfigService] },
                { provide: SharedService, useClass: SharedService, deps: [StorageService, ConfigService] },
                httpProvider,
                { provide: OauthService, useClass: OauthService, deps: [JwtHttp, Injector, SharedService, ConfigService] },
                { provide: PopupService, useClass: PopupService, deps: [ConfigService] },
                { provide: Oauth1Service, useClass: Oauth1Service, deps: [JwtHttp, PopupService, ConfigService] },
                { provide: Oauth2Service, useClass: Oauth2Service, deps: [JwtHttp, PopupService, StorageService, ConfigService] },
                { provide: LocalService, useClass: LocalService, deps: [JwtHttp, SharedService, ConfigService] },
                { provide: AuthService, useClass: AuthService, deps: [SharedService, LocalService, OauthService] },
            ]
        };
    };
    /**
     * @param {?} config
     * @return {?}
     */
    Ng2UiAuthModule.forRoot = function (config) {
        return {
            ngModule: Ng2UiAuthModule,
            providers: [
                { provide: CustomConfig, useClass: config },
                { provide: ConfigService, useClass: ConfigService, deps: [CustomConfig] },
                { provide: StorageService, useClass: BrowserStorageService, deps: [ConfigService] },
                { provide: SharedService, useClass: SharedService, deps: [StorageService, ConfigService] },
                { provide: JwtHttp, useClass: JwtHttp, deps: [Http, SharedService, ConfigService] },
                { provide: OauthService, useClass: OauthService, deps: [JwtHttp, Injector, SharedService, ConfigService] },
                { provide: PopupService, useClass: PopupService, deps: [ConfigService] },
                { provide: Oauth1Service, useClass: Oauth1Service, deps: [JwtHttp, PopupService, ConfigService] },
                { provide: Oauth2Service, useClass: Oauth2Service, deps: [JwtHttp, PopupService, StorageService, ConfigService] },
                { provide: LocalService, useClass: LocalService, deps: [JwtHttp, SharedService, ConfigService] },
                { provide: AuthService, useClass: AuthService, deps: [SharedService, LocalService, OauthService] },
            ]
        };
    };
    return Ng2UiAuthModule;
}());
Ng2UiAuthModule.decorators = [
    { type: NgModule, args: [{
                imports: [HttpModule]
            },] },
];
/**
 * @nocollapse
 */
Ng2UiAuthModule.ctorParameters = function () { return []; };
/**
 * Generated bundle index. Do not edit.
 */
export { Ng2UiAuthModule, LocalService, Oauth2Service, Oauth1Service, PopupService, OauthService, JwtHttp, SharedService, StorageService, BrowserStorageService, AuthService, ConfigService, CustomConfig };
//# sourceMappingURL=ng2-ui-auth.es5.js.map
