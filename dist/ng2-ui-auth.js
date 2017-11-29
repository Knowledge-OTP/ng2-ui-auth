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
class CustomConfig {
}
class ConfigService {
    /**
     * @param {?=} config
     */
    constructor(config) {
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
        this.resolveToken = (response) => {
            let /** @type {?} */ tokenObj = response;
            if (response instanceof Response) {
                tokenObj = response.json();
            }
            const /** @type {?} */ accessToken = tokenObj &&
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
            const /** @type {?} */ tokenRootData = this.tokenRoot &&
                this.tokenRoot.split('.').reduce((o, x) => {
                    return o[x];
                }, accessToken);
            const /** @type {?} */ token = tokenRootData ? tokenRootData[this.tokenName] : accessToken[this.tokenName];
            if (token) {
                return token;
            }
            let /** @type {?} */ tokenPath = this.tokenRoot ? this.tokenRoot + '.' + this.tokenName : this.tokenName;
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
                state: () => encodeURIComponent(Math.random().toString(36).substr(2)),
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
                state: () => encodeURIComponent(Math.random().toString(36).substr(2))
            }
        };
        Object.keys(config).forEach((key) => {
            if (typeof config[key] === "undefined") {
                return;
            }
            if (key !== 'providers') {
                this[key] = config[key];
            }
            else {
                Object.keys(config[key]).map(provider => {
                    this.providers[provider] = Object.assign(this.providers[provider] || {}, config.providers[provider]);
                });
            }
        });
    }
    /**
     * @param {?=} path
     * @return {?}
     */
    getHttpHost(path = '') {
        return window.location.origin + path;
    }
    /**
     * @return {?}
     */
    isCordovaApp() {
        return !!window['cordova'];
    }
}
ConfigService.decorators = [
    { type: Injectable },
];
/**
 * @nocollapse
 */
ConfigService.ctorParameters = () => [
    { type: CustomConfig, },
];

/**
 * @abstract
 */
class StorageService {
    /**
     * @abstract
     * @param {?} key
     * @return {?}
     */
    get(key) { }
    /**
     * @abstract
     * @param {?} key
     * @param {?} value
     * @param {?} date
     * @return {?}
     */
    set(key, value, date) { }
    /**
     * @abstract
     * @param {?} key
     * @return {?}
     */
    remove(key) { }
}
/**
 * Created by Ron on 17/12/2015.
 */
class BrowserStorageService extends StorageService {
    /**
     * @param {?} config
     */
    constructor(config) {
        super();
        this.config = config;
        this.store = {};
        this.isStorageAvailable = this.checkIsStorageAvailable(config);
        if (!this.isStorageAvailable) {
            console.warn(config.storageType + ' is not available.');
        }
    }
    /**
     * @param {?} key
     * @return {?}
     */
    get(key) {
        return this.isStorageAvailable
            ? this.config.storageType === 'cookie' || this.config.storageType === 'sessionCookie'
                ? this.getCookie(key)
                : window[this.config.storageType].getItem(key)
            : this.store[key];
    }
    /**
     * @param {?} key
     * @param {?} value
     * @param {?} date
     * @return {?}
     */
    set(key, value, date) {
        this.isStorageAvailable
            ? this.config.storageType === 'cookie' || this.config.storageType === 'sessionCookie'
                ? this.setCookie(key, value, this.config.storageType === 'cookie' ? date : '')
                : window[this.config.storageType].setItem(key, value)
            : this.store[key] = value;
    }
    /**
     * @param {?} key
     * @return {?}
     */
    remove(key) {
        this.isStorageAvailable
            ? this.config.storageType === 'cookie' || this.config.storageType === 'sessionCookie'
                ? this.removeCookie(key)
                : window[this.config.storageType].removeItem(key)
            : delete this.store[key];
    }
    /**
     * @param {?} config
     * @return {?}
     */
    checkIsStorageAvailable(config) {
        if (config.storageType === 'cookie' || config.storageType === 'sessionCookie') {
            return this.isCookieStorageAvailable();
        }
        try {
            const /** @type {?} */ supported = window && config.storageType in window && window[config.storageType] !== null;
            if (supported) {
                const /** @type {?} */ key = Math.random().toString(36).substring(7);
                window[this.config.storageType].setItem(key, '');
                window[this.config.storageType].removeItem(key);
            }
            return supported;
        }
        catch (e) {
            return false;
        }
    }
    /**
     * @return {?}
     */
    isCookieStorageAvailable() {
        try {
            const /** @type {?} */ supported = document && 'cookie' in document;
            if (supported) {
                const /** @type {?} */ key = Math.random().toString(36).substring(7);
                this.setCookie(key, 'test', new Date(Date.now() + 60 * 1000).toUTCString());
                const /** @type {?} */ value = this.getCookie(key);
                this.removeCookie(key);
                return value === 'test';
            }
            return false;
        }
        catch (e) {
            return false;
        }
    }
    /**
     * @param {?} key
     * @param {?} value
     * @param {?=} expires
     * @param {?=} path
     * @return {?}
     */
    setCookie(key, value, expires = '', path = '/') {
        document.cookie = `${key}=${value}${expires ? `; expires=${expires}` : ''}; path=${path}`;
    }
    /**
     * @param {?} key
     * @param {?=} path
     * @return {?}
     */
    removeCookie(key, path = '/') {
        this.setCookie(key, '', new Date(0).toUTCString(), path);
    }
    /**
     * @param {?} key
     * @return {?}
     */
    getCookie(key) {
        return document.cookie.replace(new RegExp(`(?:(?:^|.*;\\s*)${key}\\s*\\=\\s*([^;]*).*$)|^.*$`), '$1');
    }
}
BrowserStorageService.decorators = [
    { type: Injectable },
];
/**
 * @nocollapse
 */
BrowserStorageService.ctorParameters = () => [
    { type: ConfigService, },
];

/**
 * Created by Ron on 17/12/2015.
 */
/**
 * Created by Ron on 17/12/2015.
 */
class SharedService {
    /**
     * @param {?} storage
     * @param {?} config
     */
    constructor(storage, config) {
        this.storage = storage;
        this.config = config;
        this.tokenName = this.config.tokenPrefix ? [this.config.tokenPrefix, this.config.tokenName].join(this.config.tokenSeparator) : this.config.tokenName;
    }
    /**
     * @return {?}
     */
    getToken() {
        return this.storage.get(this.tokenName);
    }
    /**
     * @param {?=} token
     * @return {?}
     */
    getPayload(token = this.getToken()) {
        if (token && token.split('.').length === 3) {
            try {
                let /** @type {?} */ base64Url = token.split('.')[1];
                let /** @type {?} */ base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
                return JSON.parse(decodeURIComponent(encodeURIComponent(window.atob(base64))));
            }
            catch (e) {
                return undefined;
            }
        }
    }
    /**
     * @param {?} response
     * @return {?}
     */
    setToken(response) {
        if (!response) {
            console.warn('Can\'t set token without passing a value');
            return;
        }
        let /** @type {?} */ token;
        if (typeof response === 'string') {
            token = response;
        }
        else {
            token = this.config.resolveToken(response);
        }
        if (token) {
            const /** @type {?} */ expDate = this.getExpirationDate(token);
            this.storage.set(this.tokenName, token, expDate ? expDate.toUTCString() : '');
        }
    }
    /**
     * @return {?}
     */
    removeToken() {
        this.storage.remove(this.tokenName);
    }
    /**
     * @param {?=} token
     * @return {?}
     */
    isAuthenticated(token = this.getToken()) {
        // a token is present
        if (token) {
            // token with a valid JWT format XXX.YYY.ZZZ
            if (token.split('.').length === 3) {
                // could be a valid JWT or an access token with the same format
                try {
                    let /** @type {?} */ base64Url = token.split('.')[1];
                    let /** @type {?} */ base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
                    let /** @type {?} */ exp = JSON.parse(window.atob(base64)).exp;
                    // jwt with an optional expiration claims
                    if (exp) {
                        let /** @type {?} */ isExpired = Math.round(new Date().getTime() / 1000) >= exp;
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
    }
    /**
     * @param {?=} token
     * @return {?}
     */
    getExpirationDate(token = this.getToken()) {
        let /** @type {?} */ payload = this.getPayload(token);
        if (payload && payload.exp && Math.round(new Date().getTime() / 1000) < payload.exp) {
            let /** @type {?} */ date = new Date(0);
            date.setUTCSeconds(payload.exp);
            return date;
        }
        return null;
    }
    /**
     * @return {?}
     */
    logout() {
        return Observable$1.create((observer) => {
            this.storage.remove(this.tokenName);
            observer.next();
            observer.complete();
        });
    }
    /**
     * @param {?} type
     * @return {?}
     */
    setStorageType(type) {
        this.config.storageType = type;
    }
}
SharedService.decorators = [
    { type: Injectable },
];
/**
 * @nocollapse
 */
SharedService.ctorParameters = () => [
    { type: StorageService, },
    { type: ConfigService, },
];

class JwtHttp {
    /**
     * @param {?} _http
     * @param {?} _shared
     * @param {?} _config
     */
    constructor(_http, _shared, _config) {
        this._http = _http;
        this._shared = _shared;
        this._config = _config;
    }
    /**
     * @param {?} url
     * @param {?=} options
     * @return {?}
     */
    request(url, options) {
        //if the token is expired the "getExpirationDate" function returns null
        const /** @type {?} */ exp = this._shared.getExpirationDate();
        if (this._shared.getToken() &&
            (!exp || exp.getTime() + this._config.refreshBeforeExpiration > Date.now()) &&
            (options.autoRefreshToken ||
                typeof options.autoRefreshToken === 'undefined' && this._config.autoRefreshToken)) {
            return this.refreshToken()
                .switchMap(() => this.actualRequest(url, options));
        }
        if (this._config.tryTokenRefreshIfUnauthorized) {
            return this.actualRequest(url, options)
                .catch((response) => {
                if (response.status === 401) {
                    return this.refreshToken()
                        .switchMap(() => this.actualRequest(url, options));
                }
                throw response;
            });
        }
        return this.actualRequest(url, options);
    }
    /**
     * @param {?} url
     * @param {?=} options
     * @return {?}
     */
    get(url, options) {
        options = options || {};
        options.method = RequestMethod.Get;
        return this.request(url, options);
    }
    /**
     * @param {?} url
     * @param {?} body
     * @param {?=} options
     * @return {?}
     */
    post(url, body, options) {
        options = options || {};
        options.method = RequestMethod.Post;
        options.body = body;
        return this.request(url, options);
    }
    /**
     * @param {?} url
     * @param {?} body
     * @param {?=} options
     * @return {?}
     */
    put(url, body, options) {
        options = options || {};
        options.method = RequestMethod.Put;
        options.body = body;
        return this.request(url, options);
    }
    /**
     * @param {?} url
     * @param {?=} options
     * @return {?}
     */
    delete(url, options) {
        options = options || {};
        options.method = RequestMethod.Delete;
        return this.request(url, options);
    }
    /**
     * @param {?} url
     * @param {?} body
     * @param {?=} options
     * @return {?}
     */
    patch(url, body, options) {
        options = options || {};
        options.method = RequestMethod.Patch;
        options.body = body;
        return this.request(url, options);
    }
    /**
     * @param {?} url
     * @param {?=} options
     * @return {?}
     */
    head(url, options) {
        options = options || {};
        options.method = RequestMethod.Head;
        return this.request(url, options);
    }
    /**
     * @return {?}
     */
    refreshToken() {
        const /** @type {?} */ authHeader = new Headers();
        authHeader.append(this._config.authHeader, (this._config.authToken + ' ' + this._shared.getToken()));
        return this._http
            .get(this._config.refreshUrl, {
            headers: authHeader
        })
            .do((res) => this._shared.setToken(res));
    }
    /**
     * @param {?} url
     * @param {?=} options
     * @return {?}
     */
    actualRequest(url, options) {
        if (url instanceof Request) {
            url.headers = url.headers || new Headers();
            this.setHeaders(url);
        }
        else {
            options = options || {};
            this.setHeaders(options);
        }
        return this._http.request(url, options);
    }
    /**
     * @param {?} obj
     * @return {?}
     */
    setHeaders(obj) {
        obj.headers = obj.headers || new Headers();
        if (this._config.defaultHeaders) {
            Object.keys(this._config.defaultHeaders).forEach((defaultHeader) => {
                if (!obj.headers.has(defaultHeader)) {
                    obj.headers.set(defaultHeader, this._config.defaultHeaders[defaultHeader]);
                }
            });
        }
        if (this._shared.isAuthenticated()) {
            obj.headers.set(this._config.authHeader, this._config.authToken + ' ' + this._shared.getToken());
        }
    }
}
JwtHttp.decorators = [
    { type: Injectable },
];
/**
 * @nocollapse
 */
JwtHttp.ctorParameters = () => [
    { type: Http, },
    { type: SharedService, },
    { type: ConfigService, },
];

/**
 * Created by Ron on 17/12/2015.
 * @param {?} target
 * @param {...?} src
 * @return {?}
 */
function assign(target, ...src) {
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
    let /** @type {?} */ joined = [baseUrl, url].join('/');
    let /** @type {?} */ normalize = function (str) {
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
    let /** @type {?} */ result = {};
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
class PopupService {
    /**
     * @param {?} config
     */
    constructor(config) {
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
    open(url, name, options) {
        this.url = url;
        let /** @type {?} */ stringifiedOptions = this.stringifyOptions(this.prepareOptions(options));
        let /** @type {?} */ UA = window.navigator.userAgent;
        let /** @type {?} */ windowName = (this.config.cordova || UA.indexOf('CriOS') > -1) ? '_blank' : name;
        this.popupWindow = window.open(url, windowName, stringifiedOptions);
        window['popup'] = this.popupWindow;
        if (this.popupWindow && this.popupWindow.focus) {
            this.popupWindow.focus();
        }
        return this;
    }
    /**
     * @param {?} redirectUri
     * @return {?}
     */
    eventListener(redirectUri) {
        return Observable$1
            .merge(Observable$1.fromEvent(this.popupWindow, 'loadstart')
            .switchMap((event) => {
            if (!this.popupWindow || this.popupWindow.closed) {
                return Observable$1.throw(new Error('Authentication Canceled'));
            }
            if (event.url.indexOf(redirectUri) !== 0) {
                return Observable$1.empty();
            }
            let /** @type {?} */ parser = document.createElement('a');
            parser.href = event.url;
            if (parser.search || parser.hash) {
                const /** @type {?} */ queryParams = parser.search.substring(1).replace(/\/$/, '');
                const /** @type {?} */ hashParams = parser.hash.substring(1).replace(/\/$/, '');
                const /** @type {?} */ hash = this.parseQueryString(hashParams);
                const /** @type {?} */ qs = this.parseQueryString(queryParams);
                const /** @type {?} */ allParams = assign({}, qs, hash);
                this.popupWindow.close();
                if (allParams.error) {
                    throw allParams.error;
                }
                else {
                    return Observable$1.of(allParams);
                }
            }
            return Observable$1.empty();
        }), Observable$1.fromEvent(this.popupWindow, 'exit').delay(100).map(() => { throw new Error('Authentication Canceled'); })).take(1);
    }
    /**
     * @return {?}
     */
    pollPopup() {
        return Observable$1
            .interval(50)
            .switchMap(() => {
            if (!this.popupWindow || this.popupWindow.closed) {
                return Observable$1.throw(new Error('Authentication Canceled'));
            }
            let /** @type {?} */ documentOrigin = document.location.host;
            let /** @type {?} */ popupWindowOrigin = '';
            try {
                popupWindowOrigin = this.popupWindow.location.host;
            }
            catch (error) {
                // ignore DOMException: Blocked a frame with origin from accessing a cross-origin frame.
                //error instanceof DOMException && error.name === 'SecurityError'
            }
            if (popupWindowOrigin === documentOrigin && (this.popupWindow.location.search || this.popupWindow.location.hash)) {
                const /** @type {?} */ queryParams = this.popupWindow.location.search.substring(1).replace(/\/$/, '');
                const /** @type {?} */ hashParams = this.popupWindow.location.hash.substring(1).replace(/[\/$]/, '');
                const /** @type {?} */ hash = this.parseQueryString(hashParams);
                const /** @type {?} */ qs = this.parseQueryString(queryParams);
                this.popupWindow.close();
                const /** @type {?} */ allParams = assign({}, qs, hash);
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
    }
    /**
     * @param {?} options
     * @return {?}
     */
    prepareOptions(options) {
        options = options || {};
        let /** @type {?} */ width = options.width || 500;
        let /** @type {?} */ height = options.height || 500;
        return assign({
            width: width,
            height: height,
            left: window.screenX + ((window.outerWidth - width) / 2),
            top: window.screenY + ((window.outerHeight - height) / 2.5),
            toolbar: options.visibleToolbar ? 'yes' : 'no'
        }, options);
    }
    /**
     * @param {?} options
     * @return {?}
     */
    stringifyOptions(options) {
        return Object.keys(options).map((key) => {
            return key + '=' + options[key];
        }).join(',');
    }
    /**
     * @param {?} joinedKeyValue
     * @return {?}
     */
    parseQueryString(joinedKeyValue) {
        let /** @type {?} */ key, /** @type {?} */ value;
        return joinedKeyValue.split('&').reduce((obj, keyValue) => {
            if (keyValue) {
                value = keyValue.split('=');
                key = decodeURIComponent(value[0]);
                obj[key] = typeof value[1] !== 'undefined' ? decodeURIComponent(value[1]) : true;
            }
            return obj;
        }, {});
    }
}
PopupService.decorators = [
    { type: Injectable },
];
/**
 * @nocollapse
 */
PopupService.ctorParameters = () => [
    { type: ConfigService, },
];

/**
 * Created by Ron on 17/12/2015.
 */
class Oauth1Service {
    /**
     * @param {?} http
     * @param {?} popup
     * @param {?} config
     */
    constructor(http$$1, popup, config) {
        this.http = http$$1;
        this.popup = popup;
        this.config = config;
    }
    /**
     * @param {?=} options
     * @param {?=} userData
     * @return {?}
     */
    open(options, userData) {
        this.defaults = assign({}, Oauth1Service.base, options);
        let /** @type {?} */ popupWindow;
        let /** @type {?} */ serverUrl = this.config.baseUrl ? joinUrl(this.config.baseUrl, this.defaults.url) : this.defaults.url;
        if (!this.config.cordova) {
            popupWindow = this.popup.open('', this.defaults.name, this.defaults.popupOptions /*, this.defaults.redirectUri*/);
        }
        return this.http.post(serverUrl, JSON.stringify(this.defaults))
            .switchMap((response) => {
            if (this.config.cordova) {
                popupWindow = this.popup.open([this.defaults.authorizationEndpoint, this.buildQueryString(response.json())].join('?'), this.defaults.name, this.defaults.popupOptions);
            }
            else {
                popupWindow.popupWindow.location =
                    [this.defaults.authorizationEndpoint, this.buildQueryString(response.json())].join('?');
            }
            return this.config.cordova ? popupWindow.eventListener(this.defaults.redirectUri) : popupWindow.pollPopup();
        })
            .switchMap((response) => {
            let /** @type {?} */ exchangeForToken = options.exchangeForToken;
            if (typeof exchangeForToken !== 'function') {
                exchangeForToken = this.exchangeForToken.bind(this);
            }
            return exchangeForToken(response, userData);
        });
    }
    /**
     * @param {?} oauthData
     * @param {?=} userData
     * @return {?}
     */
    exchangeForToken(oauthData, userData) {
        let /** @type {?} */ data = assign({}, this.defaults, oauthData, userData);
        let /** @type {?} */ exchangeForTokenUrl = this.config.baseUrl ? joinUrl(this.config.baseUrl, this.defaults.url) : this.defaults.url;
        return this.defaults.method
            ? this.http.request(exchangeForTokenUrl, {
                body: JSON.stringify(data),
                withCredentials: this.config.withCredentials,
                method: this.defaults.method
            })
            : this.http.post(exchangeForTokenUrl, data, { withCredentials: this.config.withCredentials });
    }
    /**
     * @param {?} obj
     * @return {?}
     */
    buildQueryString(obj) {
        return Object.keys(obj).map((key) => {
            return encodeURIComponent(key) + '=' + encodeURIComponent(obj[key]);
        }).join('&');
    }
}
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
Oauth1Service.ctorParameters = () => [
    { type: JwtHttp, },
    { type: PopupService, },
    { type: ConfigService, },
];

/**
 * Created by Ron on 17/12/2015.
 */
class OauthService {
    /**
     * @param {?} http
     * @param {?} injector
     * @param {?} shared
     * @param {?} config
     */
    constructor(http$$1, injector, shared, config) {
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
    authenticate(name, userData, oauth) {
        // var injector = Injector.resolveAndCreate([Oauth1, Oauth2]);
        const /** @type {?} */ provider = this.config.providers[name].oauthType === '1.0' ? this.injector.get(Oauth1Service) : oauth;
        return provider.open(this.config.providers[name], userData || {})
            .do((response) => {
            // this is for a scenario when someone wishes to opt out from
            // satellizer's magic by doing authorization code exchange and
            // saving a token manually.
            if (this.config.providers[name].url) {
                this.shared.setToken(response);
            }
        });
    }
    /**
     * @param {?} provider
     * @param {?} opts
     * @return {?}
     */
    unlink(provider, opts) {
        opts = opts || {};
        let /** @type {?} */ url = opts.url ? opts.url : joinUrl(this.config.baseUrl, this.config.unlinkUrl);
        opts.body = JSON.stringify({ provider: provider }) || opts.body;
        opts.method = opts.method || 'POST';
        return this.http.request(url, opts);
    }
}
OauthService.decorators = [
    { type: Injectable },
];
/**
 * @nocollapse
 */
OauthService.ctorParameters = () => [
    { type: JwtHttp, },
    { type: Injector, },
    { type: SharedService, },
    { type: ConfigService, },
];

/**
 * Created by Ron on 17/12/2015.
 */
class Oauth2Service {
    /**
     * @param {?} http
     * @param {?} popup
     * @param {?} storage
     * @param {?} config
     */
    constructor(http$$1, popup, storage, config) {
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
    open(options, userData) {
        this.defaults = merge$1(options, Oauth2Service.base);
        let /** @type {?} */ url;
        let /** @type {?} */ openPopup;
        const /** @type {?} */ stateName = this.defaults.name + '_state';
        const /** @type {?} */ state = this.defaults.state;
        const /** @type {?} */ exp = new Date(Date.now() + 60 * 60 * 1000).toUTCString();
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
            .switchMap((oauthData) => {
            // when no server URL provided, return popup params as-is.
            // this is for a scenario when someone wishes to opt out from
            // satellizer's magic by doing authorization code exchange and
            // saving a token manually.
            if (this.defaults.responseType === 'token' || !this.defaults.url) {
                return Observable$1.of(oauthData);
            }
            if (oauthData.state && oauthData.state !== this.storage.get(stateName)) {
                throw 'OAuth "state" mismatch';
            }
            let /** @type {?} */ exchangeForToken = options.exchangeForToken;
            if (typeof exchangeForToken !== 'function') {
                exchangeForToken = this.exchangeForToken.bind(this);
            }
            return exchangeForToken(oauthData, userData);
        });
    }
    /**
     * @param {?} oauthData
     * @param {?=} userData
     * @return {?}
     */
    exchangeForToken(oauthData, userData) {
        let /** @type {?} */ data = assign({}, this.defaults, oauthData, userData);
        let /** @type {?} */ exchangeForTokenUrl = this.config.baseUrl ? joinUrl(this.config.baseUrl, this.defaults.url) : this.defaults.url;
        return this.defaults.method
            ? this.http.request(exchangeForTokenUrl, {
                body: JSON.stringify(data),
                withCredentials: this.config.withCredentials,
                method: this.defaults.method
            })
            : this.http.post(exchangeForTokenUrl, JSON.stringify(data), { withCredentials: this.config.withCredentials });
    }
    /**
     * @return {?}
     */
    buildQueryString() {
        let /** @type {?} */ keyValuePairs = [];
        let /** @type {?} */ urlParams = ['defaultUrlParams', 'requiredUrlParams', 'optionalUrlParams'];
        urlParams.forEach((params) => {
            if (this.defaults[params]) {
                ((this.defaults[params])).forEach((paramName) => {
                    let /** @type {?} */ camelizedName = camelCase(paramName);
                    let /** @type {?} */ paramValue = typeof this.defaults[paramName] === 'function' ?
                        this.defaults[paramName]() :
                        this.defaults[camelizedName];
                    if (paramName === 'state') {
                        let /** @type {?} */ stateName = this.defaults.name + '_state';
                        paramValue = encodeURIComponent(this.storage.get(stateName));
                    }
                    if (paramName === 'scope' && Array.isArray(paramValue)) {
                        paramValue = paramValue.join(this.defaults.scopeDelimiter);
                        if (this.defaults.scopePrefix) {
                            paramValue = [this.defaults.scopePrefix, paramValue].join(this.defaults.scopeDelimiter);
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
    }
}
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
Oauth2Service.ctorParameters = () => [
    { type: JwtHttp, },
    { type: PopupService, },
    { type: StorageService, },
    { type: ConfigService, },
];

/**
 * Created by Ron on 17/12/2015.
 * @param {?} user
 * @param {?=} userOpts
 * @return {?}
 */
function getFullOpts(user, userOpts) {
    const /** @type {?} */ opts = userOpts || {};
    if (user) {
        opts.body = typeof user === 'string' ? user : JSON.stringify(user);
    }
    opts.method = opts.method || 'POST';
    return opts;
}
class LocalService {
    /**
     * @param {?} http
     * @param {?} shared
     * @param {?} config
     */
    constructor(http$$1, shared, config) {
        this.http = http$$1;
        this.shared = shared;
        this.config = config;
    }
    /**
     * @param {?} user
     * @param {?=} opts
     * @return {?}
     */
    login(user, opts) {
        const /** @type {?} */ fullOpts = getFullOpts(user, opts);
        const /** @type {?} */ url = fullOpts.url ? fullOpts.url : joinUrl(this.config.baseUrl, this.config.loginUrl);
        return this.http.request(url, fullOpts)
            .do((response) => this.shared.setToken(response));
    }
    /**
     * @param {?} user
     * @param {?=} opts
     * @return {?}
     */
    signup(user, opts) {
        const /** @type {?} */ fullOpts = getFullOpts(user, opts);
        const /** @type {?} */ url = fullOpts.url ? fullOpts.url : joinUrl(this.config.baseUrl, this.config.signupUrl);
        return this.http.request(url, getFullOpts(user, fullOpts));
    }
}
LocalService.decorators = [
    { type: Injectable },
];
/**
 * @nocollapse
 */
LocalService.ctorParameters = () => [
    { type: JwtHttp, },
    { type: SharedService, },
    { type: ConfigService, },
];

/**
 * Created by Ron on 17/12/2015.
 */
class AuthService {
    /**
     * @param {?} shared
     * @param {?} local
     * @param {?} oauth
     */
    constructor(shared, local, oauth) {
        this.shared = shared;
        this.local = local;
        this.oauth = oauth;
    }
    /**
     * @param {?} user
     * @param {?=} opts
     * @return {?}
     */
    login(user, opts) {
        return this.local.login(user, opts);
    }
    /**
     * @param {?} user
     * @param {?=} opts
     * @return {?}
     */
    signup(user, opts) {
        return this.local.signup(user, opts);
    }
    /**
     * @return {?}
     */
    logout() {
        return this.shared.logout();
    }
    /**
     * @param {?} name
     * @param {?=} userData
     * @param {?=} oauth
     * @return {?}
     */
    authenticate(name, userData, oauth) {
        return this.oauth.authenticate(name, userData, oauth);
    }
    /**
     * @param {?} name
     * @param {?=} userData
     * @return {?}
     */
    link(name, userData) {
        return this.oauth.authenticate(name, userData);
    }
    /**
     * @param {?} provider
     * @param {?} opts
     * @return {?}
     */
    unlink(provider, opts) {
        return this.oauth.unlink(provider, opts);
    }
    /**
     * @return {?}
     */
    isAuthenticated() {
        return this.shared.isAuthenticated();
    }
    /**
     * @return {?}
     */
    getToken() {
        return this.shared.getToken();
    }
    /**
     * @param {?} token
     * @return {?}
     */
    setToken(token) {
        this.shared.setToken(token);
    }
    /**
     * @return {?}
     */
    removeToken() {
        this.shared.removeToken();
    }
    /**
     * @return {?}
     */
    getPayload() {
        return this.shared.getPayload();
    }
    /**
     * @param {?} type
     * @return {?}
     */
    setStorageType(type) {
        this.shared.setStorageType(type);
    }
    /**
     * @return {?}
     */
    getExpirationDate() {
        return this.shared.getExpirationDate();
    }
}
AuthService.decorators = [
    { type: Injectable },
];
/**
 * @nocollapse
 */
AuthService.ctorParameters = () => [
    { type: SharedService, },
    { type: LocalService, },
    { type: OauthService, },
];

/**
 * Created by Ron on 25/12/2015.
 */
class Ng2UiAuthModule {
    /**
     * @param {?} config
     * @param {?} httpProvider
     * @return {?}
     */
    static forRootWithCustomHttp(config, httpProvider) {
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
    }
    /**
     * @param {?} config
     * @return {?}
     */
    static forRoot(config) {
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
    }
}
Ng2UiAuthModule.decorators = [
    { type: NgModule, args: [{
                imports: [HttpModule]
            },] },
];
/**
 * @nocollapse
 */
Ng2UiAuthModule.ctorParameters = () => [];

/**
 * Generated bundle index. Do not edit.
 */

export { Ng2UiAuthModule, LocalService, Oauth2Service, Oauth1Service, PopupService, OauthService, JwtHttp, SharedService, StorageService, BrowserStorageService, AuthService, ConfigService, CustomConfig };
//# sourceMappingURL=ng2-ui-auth.js.map
