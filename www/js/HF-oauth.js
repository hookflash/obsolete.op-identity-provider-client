
/**
 * Hookflash Identity Provider Client Side JavaScript Library.
 */

(function (window) {

    window._HCS_IDENTITY_PROVIDER = function(options) {

        log("##### INIT #####", window.location.href, window.name);


        function generateId() {
            return (Math.floor(Math.random() * 1000000) + 1 + "");
        }

        var logInstance = generateId().substring(0, 2);
        var logIndex = 0;
        function log() {
            logIndex += 1;
            if (console) {
                console.log(arguments);
            }
            if (window.__LOGGER) {
                var args = Array.prototype.slice.call(arguments, 0);
                args.unshift("i:" + logInstance + ":" + logIndex);
                return window.__LOGGER.log.apply(null, args);
            } else {
    //            console.log(arguments);
            }
        }


        var ASSERT = {
            equal: function (actual, expected, message) {
                if (actual !== expected) {
                    console.error("ASSERT", message);
                    throw new Error("Assertion error: " + message);
                }
            }
        }

        var Client = function (options) {
            var self = this;
            self.options = options;
            ASSERT.equal(typeof self.options.domain, "string", "'options.domain' must be set");
            self.session = null;
            self.ready = false;
            self.visible = false;
        }
        Client.prototype.init = function (window) {
            var self = this;
            log("Client->init()");

            var lastPostedMessage = null;
            self.postObject = function (message) {
                message = JSON.stringify(message, null, 4);
                lastPostedMessage = message;
                if (
                    window.opener &&
                    typeof window.opener.postMessage === "function"
                ) {
                    log("window.opener.postMessage", message);
                    // TODO: Only post to specific opener domains.
                    window.opener.postMessage(message, "*");
                } else
                if (
                    window.parent &&
                    typeof window.parent.postMessage === "function"
                ) {
                    log("window.parent.postMessage", message);
                    // TODO: Only post to specific parent frame domains.
                    window.parent.postMessage(message, "*");

                } else {
                    throw new Error("Unable to message parent window!");
                }
            }

            // Global cross-domain message handler.
            window.onmessage = function (message) {
                if (!message.data) return;
                if (message.data === lastPostedMessage) return;
                log("window.onmessage", "message.data", message.data);
                try {
                    var data = message.data;
                    if (typeof data === "string") {
                        data = JSON.parse(data);
                    }
                    if (data.notify) {
                        if (data.notify.$handler == "identity") {

                            if (!self.ready) {
                                if (data.notify.$method == "identity-access-complete") {
                                    // We are being notified that login was successful in another window.
                                    // So we reload the session and assume we have access to the successful data as well to we set `self.ready` to `true`.
                                    // TODO: Should `self.ready` be set when loading session data within `self.loadSession()`?
                                    self.ready = true;
                                    return self.loadSession();
                                }

                                throw new Error("Cannot handle '" + data.notify.$handler + ":" + data.notify.$method + "'. 'identity-access-window' result not yet received!");
                            }

                            if (data.notify.$method == "identity-access-reset") {
                                return self.handleAccessReset(data.notify);
                            } else
                            if (data.notify.$method == "identity-access-start") {
                                return self.handleAccessStart(data.notify);
                            } else {
                                throw new Error("Method '" + data.notify.$method + "' for notify handler '" + data.notify.$handler + "' not implemented!");
                            }
                        } else {
                            throw new Error("Notify handler '" + data.notify.$handler + "' not implemented!");
                        }
                    } else
                    if (data.result) {
                        if (data.result.$handler == "identity") {
                            if (data.result.$method == 'identity-access-window') {
                                if (data.result.$id === self._sendAccessWindow__id) {
                                    self.ready = true;
                                    log("Client->init() - self.session", self.session);
                                    if (self.session) {

                                        log("Client->init() - continue after reload with current session status:", self.session.status);

                                        if (self.session.status === "requested") {
                                            return self.proceedWithLogin();
                                        } else
                                        if (self.session.status === "proceeding") {                                    
                                            return self.proceedAfterLogin();
        //                                } else
        //                                if (self.session.status === "loggedin") {
        //                                    return self.sendAccessComplete();
                                        }
                                    }
                                    // Nothing to do until we get a 'identity-access-start' message
                                    // which will set 'self.session' and keep it in local storage across reloads.
                                    log("Client->init() - WARNING: IGNORING REQUEST", data.result);
                                    return;
                                }
                            } else {
                                throw new Error("Method '" + data.result.$method + "' for result handler '" + data.result.$handler + "' not implemented!");
                            }
                        } else {
                            throw new Error("Result handler '" + data.result.$handler + "' not implemented!");
                        }
                    } else
                    if (data.request) {
                        if (!self.ready) {
                            throw new Error("Cannot handle '" + data.request.$handler + ":" + data.request.$method + "'. 'identity-access-window' result not yet received!");
                        }
                        if (data.request.$handler == "identity") {
                            if (data.request.$method === "identity-access-lockbox-update") {
                                return self.handleAccessLockboxUpdate(data.request);
                            } else
                            if (data.request.$method === "identity-access-rolodex-credentials-get") {
                                return self.handleAccessRolodexCredentialsGet(data.request);
                            } else {
                                throw new Error("Method '" + data.request.$method + "' for request handler '" + data.request.$handler + "' not implemented!");
                            }
                        } else {
                            throw new Error("Request handler '" + data.request.$handler + "' not implemented!");
                        }
                    }
                } catch (err) {
                    log("ERROR", "window.onmessage", err.message, err.stack);
                }
            };

            self.loadSession();

            log("Client->init() - self.session", self.session);

            // If we are loading page for new login session we reset any existing status if present.
            // But only if we are not re-initializing in login window (reinit=false).
            if (
                self.session &&
                self.session.status &&
                !/reload=true/.test(window.location.search) &&
                !/reinit=false/.test(window.location.search)
            ) {
                log("Client->init() - Reset session because: " + window.location.search);
                self.storeSession(null);
                return self.redirect(window.location.href);
            }

            return self.sendAccessWindow(false);
        }
        Client.prototype.redirect = function (url, top) {
            var self = this;
            log("Client->redirect(url)", url);
            if (/^\//.test(url)) {
                url = window.location.protocol + "//" + window.location.host + url;
            }
            if (top) {
                log("Client->redirect() - window.parent.location", url);
                window.parent.location = url;
        //        log("Client->redirect() - window.top.location", url);
        //        window.top.location = url;
            } else {
                log("Client->redirect() - window.location", url);
                window.location = url;
            }
        }
        Client.prototype.callServer = function (request, callback) {
            var self = this;
            log("Client->callServer(request)", request);
            return $.ajax({
                url : "/" + request.$method,
                type : "POST",
                data : JSON.stringify({
                    "request": request
                }),
                contentType: "application/json",
                // callback handler that will be called on success
                success : function(response, textStatus, jqXHR) {
                    log("Client->callServer() - success", response);
                    var result = null;
                    if (typeof response === "string") {
                        try {
                            result = JSON.parse(response).result;
                        } catch (err) {
                            log("Client->callServer() - success", response);
                            return callback(new Error("Error '" + err.message + "' parsing JSON response!"));
                        }
                    } else {
                        result = response.result;
                    }            
                    if (result.error) {
                        // result.error.reason.message
                        // result.error.reason.$id
                        log("Client->callServer() - error", result.error.reason);
                    }
                    return callback(null, result);
                },
                // callback handler that will be called on error
                error : function(jqXHR, textStatus, errorThrown) {
                    log("Client->callServer() - error", textStatus);
                    return callback(new Error("Error '" + textStatus + "' calling identity provider API"));
                }
            });
        }
        Client.prototype.storeSession = function (session) {
            var self = this;
            log("Client->storeSession(session)", session);
            self.session = session;
            window.localStorage["opid-session"] = JSON.stringify(session);
        }
        Client.prototype.loadSession = function () {
            var self = this;
            log("Client->loadSession()");
            self.session = window.localStorage["opid-session"] || null;
            if (self.session) {
                try {
                    self.session = JSON.parse(self.session);
                } catch (err) {
                    log("ERROR", "Client->loadSession()", "Error '" + err.message + "' parsing session:", self.session);
                    self.session = null;
                }
            }
        }
        // @see http://docs.openpeer.org/OpenPeerProtocolSpecification/#IdentityServiceRequests-IdentityAccessWindowRequest
        Client.prototype.sendAccessWindow = function (visible) {
            var self = this;
            log("Client->sendAccessWindow(visible)", visible);
            self.visible = visible || false;
            self.ready = false;
            self._sendAccessWindow__id = generateId();
            return self.postObject({
                "request" : {
                    "$domain": self.options.domain,
                    // TODO: Document the fact that the `$appid` is set to `""` here because it is not yet known.
                    "$appid": "",
                    "$id": self._sendAccessWindow__id,
                    "$handler": "identity",
                    "$method": "identity-access-window",
                    "browser": {
                        "ready": true,
                        "visibility": self.visible,
                        "top": (
                            self.session &&
                            self.session.required &&
                            self.session.required.browser &&
                            self.session.required.browser.top
                        ) || false
                    }
                }
            });
        }
        Client.prototype.handleAccessReset = function (message) {
            var self = this;
            log("Client->handleAccessReset()");
            self.storeSession(null);
            return self.redirect(message.browser.outerFrameURL, true);
        }

        Client.prototype._verifyWindowVisibility = function () {
            var self = this;
            log("Client->_verifyWindowVisibility()");
            if (self.session.required.browser.visibility) {
                if (!self.visible) {
                    if (self.session.requested.browser.visibility === "visible") {
                        // We can proceeed as browser is already visible.
                        self.visible = true;
                    } else
                    if (self.session.requested.browser.visibility === "hidden") {
                        throw new Error("Trying to login with method that requires login window to be shown but app is stating that 'browser.visibility = hidden'");
                    } else
                    if (self.session.requested.browser.visibility === "visible-on-demand") {
                        self.sendAccessWindow(true);
                        return true;
                    }
                }
            } else {
                if (self.visible) {
                    if (
                        self.session.requested.browser.visibility === "hidden" ||
                        self.session.requested.browser.visibility === "visible-on-demand"
                    ) {
                        // We can proceeed as browser is already hidden.
                        self.visible = false;
                    } else
                    if (self.session.requested.browser.visibility === "visible") {
                        self.sendAccessWindow(false);
                        return true;
                    }
                }
            }
            log("Client->_verifyWindowVisibility() - no redirect");
            return false;
        }

        // @see http://docs.openpeer.org/OpenPeerProtocolSpecification/#IdentityServiceRequests-IdentityAccessStartNotification
        Client.prototype.handleAccessStart = function (message) {
            var self = this;
            log("Client->handleAccessStart(message)", message);

            function makeAuthToken() {
                var sha1 = CryptoJS.algo.SHA1.create();
                sha1.update(generateId() + ":" + generateId() + ":" + generateId());
                return sha1.finalize().toString();
            }

            console.log("Client->handleAccessStart(message) - message.identity before adjustments", message.identity);

            // Determine type of login or let user choose by default.
            var authType = null;
            if (
                !message.identity.base &&
                message.identity.uri
            ) {
                message.identity.base = message.identity.uri.replace(/^(identity:\/\/[^\/]+\/).+$/, "$1");
            }

            if (!message.identity.provider) {
                message.identity.provider = message.identity.base;
            }

            console.log("Client->handleAccessStart(message) - message.identity after adjustments", message.identity);

            if (message.identity.base) {
//                if (
//                    message.identity.base &&
//                    message.identity.provider
//                ) {
                    if (message.identity.base === ("identity://" + message.identity.provider + "/")) {
                        // Let user choose login.
                        authType = null;
                    } else
                    if (message.identity.base === "identity://facebook.com/") {
                        authType = "facebook_v1";
                    } else
                    if (message.identity.base === "identity://twitter.com/") {
                        authType = "twitter";
                    } else {
                        try {
                            if (message.identity.base === ("identity://" + message.identity.provider.match(/^(.+?)\.identity\./)[1].replace(/-{2}/g, "__DASH__").replace(/-/g, ".").replace(/__DASH__/g, "-") + "/")) {
                                authType = "oauth";
                            }
                        } catch(err) {}
                    }
//                }
            }

            log("Client->handleAccessStart(message) - authType", authType);

            var session = {
                $domain: message.$domain,
                $appid: message.$appid,
                requested: {
                    identity: message.identity,
                    browser: message.browser
                },
                authToken: makeAuthToken(),
                authType: authType,
                required: {
                    browser: {
                        // Browser must be visible for user to login
                        visibility: !(typeof message.identity.reloginKey === "string"),
                        // Login process must happen in top window
                        top: true
                    }
                },
                status: "requested"
            };

            self.storeSession(session);

            if (self._verifyWindowVisibility()) {
                return;
            }

            return self.proceedWithLogin();
        }
        Client.prototype.forceFreshLogin = function () {
            console.log("forceFreshLogin() - self.session", self.session);
            // NOTE: We reconstruct the session object the way it would be after handleAccessStart() without a reloginKey.
            self.session.status = "requested";
            self.session.required.browser.visibility = true;
            delete self.session.requested.identity.reloginKey;
            self.storeSession(session);
            if (self._verifyWindowVisibility()) {
                return;
            }
            return self.proceedWithLogin();
        }
        Client.prototype.proceedWithLogin = function () {
            var self = this;
            log("Client->proceedWithLogin()");
            if (!self.session) {
                throw new Error("Must have an active session");
            }
            if (self.session.status !== "requested") {
                throw new Error("Session status must be set to 'requested'");
            }

            delete self.session.status;
            self.storeSession(self.session);


            function doLogin() {
                var top = false;
                var callbackURL = null;
                if (self.session.required.browser.top && window.top !== window) {
                    top = true;
                    callbackURL = self.session.requested.browser.outerFrameURL;
                } else {
                    callbackURL = window.location.href;
                }

                return self.callServer({
                    "$domain": self.session.$domain,
                    "$appid": self.session.$appid,
                    "$id": generateId(),
                    "$handler": "identity-provider",
                    "$method": "oauth-provider-authentication",
                    "clientAuthenticationToken": self.session.authToken,
                    "callbackURL": callbackURL,
                    "identity": {
                        "type": self.session.authType,
                        "base": self.session.requested.identity.base,
                        "reloginKey": self.session.requested.identity.reloginKey || null
                    }
                }, function (err, result) {
                    if (err) throw err;

                    try {

                        ASSERT.equal(typeof result.serverAuthenticationToken, "string", "'result.serverAuthenticationToken' must be set!");

                        self.session.serverAuthenticationToken = result.serverAuthenticationToken;

                        if (result.providerRedirectURL) {

                            log("Client->proceedWithLogin() - got redirect URL", self.session);

                            delete self.session.requested.identity.reloginKey;
                            self.session.status = "requested";
                            self.session.required.browser.visibility = true;
                            self.storeSession(self.session);

                            if (self._verifyWindowVisibility()) {
                                log("Client->proceedWithLogin() - stop before redirect due to browser not visible");
                                return;
                            }

                            self.session.status = "proceeding";
                            self.storeSession(self.session);

                            return self.redirect(result.providerRedirectURL, top);
                        } else {

                            self.session.status = "proceeding";
                            self.storeSession(self.session);

                            return self.proceedAfterLogin();
                        }
                    } catch(err) {
                        log("Client->proceedWithLogin() - error: " + err.stack);
                        throw err;
                    }
                });
            }


            $("#op-spinner").addClass("op-hidden");

            // User must choose type of login!

            if (
                !self.options.configuredServices ||
                self.options.configuredServices.length === 0
            ) {
                log("Client->proceedWithLogin() - no services configured!");

                $("#op-service-none-view").removeClass("op-hidden");
                return;
            } else {

                log("Client->proceedWithLogin() - self.options.configuredServices:", self.options.configuredServices);

                // If only one service is configured we proceed with that login.
                if (self.options.configuredServices.length === 1) {
                    self.session.authType = self.options.configuredServices[0].name;
                    log("Client->proceedWithLogin() - proceed with only configured service:", self.session.authType);
                    self.storeSession(self.session);
                    return doLogin();
                } else
                if (self.session.authType) {
                    log("Client->proceedWithLogin() - proceed with requested service:", self.session.authType);
                    return doLogin();
                } else {
                    log("Client->proceedWithLogin() - let user pick login service");                                               
                    self.options.configuredServices.forEach(function (service) {
                        $("#op-service-" + service.name + "-view").removeClass("op-hidden");
                        $("#op-service-" + service.name + "-view BUTTON").click(function() {
                            self.session.authType = service.name;
                            self.storeSession(self.session);
                            doLogin();
                            return false;
                        });
                    });

                    self.session.status = "requested";
                    self.session.required.browser.visibility = true;
                    self.storeSession(self.session);

                    if (self._verifyWindowVisibility()) {
                        log("Client->proceedWithLogin() - show window so user can pick");
                        return;
                    }
                    return;
                }
                return;
            }
        }
        // TODO: Combine with 'Client.prototype.proceedWithLogin'?
        Client.prototype.proceedAfterLogin = function () {
            var self = this;
            log("Client->proceedAfterLogin()");
            if (!self.session) {
                throw new Error("Must have an active session");
            }
            if (self.session.status !== "proceeding") {
                throw new Error("Session status must be set to 'proceeding'");
            }

            delete self.session.status;
            self.storeSession(self.session);

            return self.callServer({
                "$domain": self.session.$domain,
                "$appid": self.session.$appid,
                "$id": generateId(),
                "$handler": "identity-provider",
                "$method": "login",
                "proof" : {
                    "clientAuthenticationToken": self.session.authToken,
                    "serverAuthenticationToken": self.session.serverAuthenticationToken
                },
                "identity": {
                    "type": self.session.authType,
                    "base": self.session.requested.identity.base
                }
            }, function (err, result) {
                if (err) throw err;

                if (result.error) {
                    if (result.error.$id === 403) {

                        // Looks like our relogin token is not working.
                        // So we start a fresh login session.

                        log("Client->proceedAfterLogin() - cannot login - forcing fresh login");

                        return self.forceFreshLogin();
                    }
                }

                ASSERT.equal(typeof result.identity.accessToken, "string", "'result.identity.accessToken' must be set!");
                ASSERT.equal(typeof result.identity.accessSecret, "string", "'result.identity.accessSecret' must be set!");
                ASSERT.equal(typeof result.identity.accessSecretExpires, "number", "'result.identity.accessSecretExpires' must be set!");

                // TODO: Generate relogin key on client or add something to it so that part transferred from server is not enough alone to login?
                ASSERT.equal(typeof result.identity.reloginKey, "string", "'result.identity.reloginKey' must be set!");

                self.session.login = {
                    identity: result.identity,
                    lockbox: result.lockbox
                };
                self.session.status = "loggedin";
                self.storeSession(self.session);

        // TODO: Implement the two-part password set.
        /*
                if (self.session.authType === "oauth") {
                    if (!loginResponseJSON.result.lockbox.key) {
                        // if first time seen identity
                        getHostingData(loginResponseJSON, true);
                    } else {
                        // if seen this before
                        getHostingData(loginResponseJSON, false);
                    }
                } else {
        */
        /*
                    var reloginKey = self.session.requested.identity.reloginKey || "";
                    if (!reloginKey) {
                        // TODO: Generate login key based on password parts.
                        //if (identity.passwordStretched && identity.reloginEncryptionKey && data.identity.reloginKeyServerPart) {
                        //    reloginKey = encrypt(identity.passwordStretched + "--" + data.identity.reloginKeyServerPart, identity.reloginEncryptionKey);
                        //}
                        // TODO: Remove 'result.identity.reloginKey' from response. [Security]
                        reloginKey = self.session.login.identity.reloginKey;
                    }
        */
                    var lockboxKey = self.session.login.lockbox.key || null;
                    if (lockboxKey) {
                        // TODO: Implement key hashing properly instead of getting key from 'result.identity.accessSecret'. [Security]
                        lockboxKey = self.session.login.identity.accessSecret;
                        /*
                        var iv = hash(identity.secretSalt);
                        log("identityAccessCompleteNotify", "iv", iv);
                        var key = decryptLockbox(lockboxkey, identity.passwordStretched, identity.identifier, iv);
                        log("identityAccessCompleteNotify", "key", key);
                        */
                    }

                    self.session.reloginKey = self.session.login.identity.reloginKey;
                    self.session.lockboxKey = lockboxKey;

                    self.storeSession(self.session);

                    return self.sendAccessComplete();
        //        }
            });
        }
        Client.prototype.sendAccessComplete = function() {
            var self = this;
            log("Client->sendAccessComplete()");
            if (!self.session) {
                throw new Error("Must have an active session");
            }
            if (self.session.status !== "loggedin") {
                throw new Error("Session status must be set to 'loggedin'");
            }
            var notify = {
                "$domain": self.session.$domain,
                "$appid": self.session.$appid,
                "$id": generateId(),
                "$handler": "identity",
                "$method": "identity-access-complete",
                "identity": {
                    "accessToken": self.session.login.identity.accessToken,
                    "accessSecret": self.session.login.identity.accessSecret,
                    "accessSecretExpires": self.session.login.identity.accessSecretExpires,                            
                    "uri": self.session.login.identity.uri,
                    "provider": self.session.requested.identity.provider,
                    "reloginKey": self.session.reloginKey,

                    // HACK: Remove after protocol fixes when peer-lookup is done on startup.
                    "name": self.session.login.identity.name,
                    "profile": self.session.login.identity.profile,
                    "vprofile": self.session.login.identity.vprofile,
                    "feed": self.session.login.identity.feed,
                    "avatars": self.session.login.identity.avatars
                }
            };
            if (self.session.lockboxKey) {
                notify.lockbox = {
                    "domain": self.session.$domain,
                    "key": self.session.lockboxKey,
                    "reset": self.session.login.lockbox.reset || false
                };
            }

            $("DIV.view").addClass("op-hidden");
            $("#op-spinner").removeClass("op-hidden");

            return self.postObject({
                "notify": notify
            });
        }
        Client.prototype.handleAccessLockboxUpdate = function (request) {
            var self = this;
            log("Client->handleAccessLockboxUpdate()", request);
            if (!self.session) {
                throw new Error("Must have an active session");
            }
            if (self.session.status !== "loggedin") {
                throw new Error("Session status must be set to 'loggedin'");
            }

            var lockboxKey = request.lockbox.key;
            // TODO: Encrypt locbox key. [Security]
            //var keyEncrypted = encryptLockbox(lockboxKey, identity.passwordStretched, identity.identifier, identity.secretSalt);
            var keyEncrypted = lockboxKey;

            return self.callServer({
                "$domain": request.$domain,
                "$appid": request.$appid,
                "$id": request.$id,
                "$handler": "identity-provider",
                "$method": "lockbox-half-key-store",
                "nonce": request.nonce,
                "identity": {
                    "accessToken": request.identity.accessToken,
                    "accessSecretProof": request.identity.accessSecretProof,
                    "accessSecretProofExpires": request.identity.accessSecretProofExpires,            
                    // TODO: What is this used for?
                    "type": self.session.authType,
                    // TODO: What is this used for?
                    "identifier": "",
                    "uri": request.identity.uri
                },
                "lockbox": {
                    "keyEncrypted": keyEncrypted
                }
            }, function (err, result) {
                if (err) throw err;
                result.$handler = request.$handler;
                result.$method = request.$method;
                return self.postObject({
                    "result": result
                });
            });
        }
        Client.prototype.handleAccessRolodexCredentialsGet = function (request) {
            var self = this;
            log("Client->handleAccessRolodexCredentialsGet()", request);
            if (!self.session) {
                throw new Error("Must have an active session");
            }
            if (self.session.status !== "loggedin") {
                throw new Error("Session status must be set to 'loggedin'");
            }
            return self.callServer({
                "$domain": request.$domain,
                "$appid": request.$appid,
                "$id": request.$id,
                "$handler": "identity-provider",
                "$method": "identity-access-rolodex-credentials-get",
                "nonce": request.nonce,
                "identity": {
                    "accessToken": request.identity.accessToken,
                    "accessSecretProof": request.identity.accessSecretProof,
                    "accessSecretProofExpires": request.identity.accessSecretProofExpires,            
                    // TODO: What is this used for?
                    "uri": request.identity.uri,
                    "provider": request.identity.provider
                }
            }, function (err, result) {
                if (err) throw err;
                result.$handler = request.$handler;
                result.$method = request.$method;
                return self.postObject({
                    "result": result
                });
            });
        }


        try {

            var client = new Client(options);
            client.init(window);

            return client;

        } catch (err) {
            log("ERROR", "init", err.message, err.stack);
            throw err;
        }
    };

})(window);
