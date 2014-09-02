
/**
 * Hookflash Identity Provider API
 */

(function(window) {

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

    var lastPostedMessage = null;
/* VERIFIED */
    function postMessage(message, targetOrigin) {
        log("window.parent.postMessage", message, targetOrigin);
        lastPostedMessage = message;
        window.parent.postMessage(message, targetOrigin);
    }


    var HF_LoginAPI = window.HF_LoginAPI = function() {

        log("##### INIT #####", window.location.href);

        var identity = {};                      // identity
        var identityAccessStart;                // identityAccessStart notify
        var initData;                           // init data
        var imageBundle = {};                   // imageBundle (used for avatar upload)
        var $appid = null;
        var $identityProviderDomain;            // used for every request
        var serverMagicValue;                   // serverMagicValue
        var waitForNotifyResponseId;            // id of "identity-access-window" request
        var secretSetResults = 0;               //
        var secretGetResults = 0;               //
        var loginResponseJSON = null; 

        //  passwordServers
        var passwordServer1 = null;
        var passwordServer2 = null;




/* VERIFIED */
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
        log("window.parent.postMessage", message);
        // TODO: Only post to parent frame domain.
        window.parent.postMessage(message, "*");
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
                if (!self.ready) {
                    throw new Error("Cannot handle '" + data.notify.$handler + ":" + data.notify.$method + "'. 'identity-access-window' result not yet received!");
                }
                if (data.notify.$handler == "identity") {
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
    if (!/reload=true/.test(window.location.search) && self.session && self.session.status) {
        log("Client->init() - Reset session because reload != true");
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
        log("Client->redirect() - window.top.location", url);
        window.top.location = url;
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
                "visibility": self.visible
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

    // TODO: Derive `message.identity.provider` from `message.identity.base` if not set.

    // Determine type of login or let user choose by default.
    var authType = null;
    if (message.identity.base) {
        if (message.identity.base === "identity://facebook.com") {
            authType = "facebook";
        } else {
            authType = "oauth";
        }
    }

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
                "base": "identity://" + self.session.requested.identity.provider + "/",
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
                        log("Client->proceedWithLogin() - stop after redirect due to browser not visible");
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

    if (self.session.authType) {
        return doLogin();
    }

    // User must choose type of login!
    // TODO: Only show configured services.
    $("#op-service-oauth-view").removeClass("op-hidden");
    $("#op-service-oauth-view BUTTON").click(function() {
        self.session.authType = "oauth";
        self.storeSession(self.session);
        doLogin();
        return false;
    });
    $("#op-service-facebook-view").removeClass("op-hidden");
    $("#op-service-facebook-view BUTTON").click(function() {
        self.session.authType = "facebook";
        self.storeSession(self.session);
        doLogin();
        return false;
    });
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
            "base": "identity://" + self.session.requested.identity.provider + "/"
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
            "reloginKey": self.session.reloginKey
        }
    };
    if (self.session.lockboxKey) {
        notify.lockbox = {
            "domain": self.session.$domain,
            "key": self.session.lockboxKey,
            "reset": self.session.login.lockbox.reset || false
        };
    }
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




        var init = function(bundle) {
            try {


                var client = new Client({
                    domain: bundle.$identityProvider
                });
                client.init(window);

return;

                initData = bundle;
                $identityProviderDomain = initData.$identityProvider;

                passwordServer1 = initData.passwordServer1;
                passwordServer2 = initData.passwordServer2;

                log("INFO", "init bundle", initData);

/* VERIFIED */




                // Buffer logging calls until we have an `$appid` available.
//                window.__LOGGER.setChannel(false);
/*
                // reload scenario
                if (initData.identityServiceAuthenticationURL) {

                    log("##### Finish oAuth #####", window.location.href);

                    finishOAuthScenario(initData.identityServiceAuthenticationURL);
                } else {

                    log("##### Signal Init #####", window.location.href);
                    identityAccessWindowNotify(false);
                }
*/                
            } catch (err) {
                log("ERROR", "init", err.message, err.stack);
            }
        };
        
        // Global cross-domain message handler.
        window.onmessage = function(message) {
return;
            if (!message.data) return;
            if (message.data === lastPostedMessage) return;

            try {
                var data = (typeof message.data === "string") ? JSON.parse(message.data) : message.data;

                // Wait for `init()` to run before we process messages.
                Q.when(ready.promise).then(function() {

                    log("window.onmessage", "data", data);

                    if (data.notify) {

                        $appid = data.notify.$appid;
//                        window.__LOGGER.setChannel("identity-provider-js-" + $appid);

                        if (data.notify.$method == "identity-access-start") {
                            // start login/sign up procedure
                            identityAccessStart = data.notify;

                            log("window.onmessage", "identityAccessStart", identityAccessStart);
/* VERIFIED */

handleAccessStart(data.notify);

// TODO: Implement relogin.
/*
                            if (identityAccessStart.identity.reloginKey !== undefined) {
                                //relogin
                                startRelogin();
                            } else {
                                startLogin();
                            }
*/
                        }
                    } else
                    if (data.result) {

                        $appid = data.result.$appid;
//                        window.__LOGGER.setChannel("identity-provider-js-" + $appid);

                        if (data.result.$method == 'identity-access-window') {

                            log("window.onmessage", "identity", identity);
                            log("window.onmessage", "waitForNotifyResponseId", waitForNotifyResponseId);

/* VERIFIED */
if (data.result.$id === NEW_instanceId) {
    console.log("Inner frame ready!");
}

// TODO: WHat is the rest here for?

                            if (
                                data.result.$id === waitForNotifyResponseId &&
                                identity.redirectURL
                            ) {
                                return redirectToURL(identity.redirectURL);
                            }
                        }
                    } else
                    if (data.request) {

                        $appid = data.request.$appid;
//                        window.__LOGGER.setChannel("identity-provider-js-" + $appid);

                        if (data.request.$method === "identity-access-lockbox-update") {
                            identityAccessLockboxUpdate(data);
                        } else
                        if (data.request.$method === "identity-access-rolodex-credentials-get") {
                            identityAccessRolodexCredentialsGet(data);
                        }
                    }
                }).fail(function(err) {
                    log("ERROR", "window.onmessage", err.message, err.stack);
                });
            } catch (err) {
                if (!$appid) {
                    window.__LOGGER.setChannel("identity-provider-js-all");                    
                }
                log("window.onmessage", "message.data", message.data);
                log("ERROR", "window.onmessage", err.message, err.stack);
            }
        };





        var permissionGrantComplete = function(id, permisions) {
            return postMessage(JSON.stringify({
                "notify" : {
                    "$domain" : $identityProviderDomain,
                    "$appid" : $appid,
                    "$id" : generateId(),
                    "$handler" : "lockbox",
                    "$method" : "lockbox-permission-grant-complete",
                    "grant" : {
                        "$id" : id,
                        "permissions" : {
                            "permission" : permisions
                        }
                    }
                }
            }), "*");
        };

        /**
         * Redirects parent page to URL.
         */
        var redirectToURL = function(url) {
            log("redirectToURL", url);
            localStorage.clientAuthenticationToken = identity.clientAuthenticationToken;
            localStorage.identityAccessStart = JSON.stringify(identityAccessStart);
            localStorage.$appid = $appid;
            log("set localStorage", {
                clientAuthenticationToken: localStorage.clientAuthenticationToken,
                identityAccessStart: localStorage.identityAccessStart,
                $appid: $appid
            });
            window.top.location = url;
        };

        var identityAccessWindowNotify = function(visibility) {
            log("identityAccessWindowNotify", visibility);
            return postMessage(JSON.stringify({
                "request" : {
                    "$domain" : $identityProviderDomain,
                    // TODO: Document the fact that the `$appid` is set to `""` here because it is not yet known.
                    "$appid" : "",
                    "$id" : NEW_instanceId,
                    "$handler" : "identity",
                    "$method" : "identity-access-window",
                    "browser" : {
                        "ready" : true,
                        "visibility" : visibility
                    }
                }
            }), "*");
        };

        /**
         * Decrypts lockbox keyhalf.
         * 
         * @return decrypted lockbox key half 
         */
        var decryptLockbox =  function(lockboxKeyHalf, passwordStretched, userId, userSalt) {
            var key = hmac(passwordStretched, userId);
            var iv = hash(userSalt);
            var dec = decrypt(lockboxKeyHalf, key, iv);
            return dec;
        };

        /**
         * Encrypts lockbox key half.
         * 
         * @return encrypted lockbox key half
         */
        var encryptLockbox = function(lockboxKeyHalf, passwordStretched, userId, userSalt) {
            var key = hmac(passwordStretched, userId);
            var iv = hash(userSalt);
            var enc = encrypt(lockboxKeyHalf, key, iv);
            return enc;
        };



        var startLogin = function() {
            try {
                log("startLogin");
                setType(identityAccessStart);
                if (
                    identity.type === "facebook" ||
                    identity.type === "linkedin" ||
                    identity.type === "twitter"
                ) {
                    startLoginOauth();
                } else {
                    throw new Error("Don't know how to proceed!");
                }
            } catch(err) {
                log("ERROR", "startLogin", err.message, err.stack);
            }
        };

        var showView = function (name) {
            $("#op-spinner").addClass("op-hidden");
            $('DIV[id^="op-"][id$="-view"]').addClass("op-hidden");
            if (!Array.isArray(name)) {
                name = [ name ];
            }
            name.forEach(function(name) {
                if (name === "loading") {
                    $("#op-spinner").removeClass("op-hidden");
                } else {
                    $('DIV[id^="op-"][id$="-view"]#op-' + name + '-view').removeClass("op-hidden");
                }
            });
        }



        var startRelogin = function() {
            log("startRelogin");
            setType(identityAccessStart);
            //getSalts (and then call relogin)
            getIdentitySalts(relogin);
        };

        var relogin = function() {
            log("relogin");
            var reloginKeyDecrypted = decrypt(identityAccessStart.identity.reloginKey, identity.reloginEncryptionKey);
            var reloginKeyServerPart = reloginKeyDecrypted.split("--")[1];
            return login({
                "request": {
                    "$domain": $identityProviderDomain,
                    "$id": generateId(),
                    "$handler": "identity-provider",
                    "$method": "login",
                    "identity": {
                        "reloginKeyServerPart": reloginKeyServerPart
                    }
                }
            });
        };

        var setType = function(identityAccessStart) {
            log("setType", identityAccessStart);
            if (identityAccessStart.identity.type) {
                identity.type = identityAccessStart.identity.type;
                identity.uri = "identity://" + identity.type + "/";
                identity.identifier = identityAccessStart.identity.identifier || "";
                return;
            }
            var id = identityAccessStart.identity.base || identityAccessStart.identity.uri;
            if (id.startsWith("identity:phone:")) {
                identity.type = "phone";
                identity.uri = "identity:phone:";
                identity.identifier = identityBase.substring(15, id.length);
            } else
            if (id.startsWith("identity:email:")) {
                identity.type = "email";
                identity.uri = "identity:email:";
                identity.identifier = id.substring(15, identityBase.length);
            } else
            if (id.startsWith("identity://" + $identityProviderDomain + "/linkedin.com")) {
                identity.type = "linkedin";
                identity.uri = "identity://" + $identityProviderDomain
                        + "/linkedin.com/";
            } else
            if (id.startsWith("identity://facebook.com")) {
                identity.type = "facebook";
                identity.uri = "identity://facebook/";
            } else
            if (id.startsWith("identity://twitter.com")) {
                identity.type = "twitter";
                identity.uri = "identity://twitter/";
            } else {
                log("WARN", "Unknown identity type", id);
            }
        };

        var getIdentitySalts = function(callback) {
            log("getIdentitySalts");
            var data = {
                "request" : {
                    "$domain" : $identityProviderDomain,
                    "$id" : generateId(),
                    "$handler" : "identity-provider",
                    "$method" : "identity-salts-get",

                    "identity" : {
                        "type" : identity.type,
                        "identifier" : identity.identifier
                    }
                }
            };
            $.ajax({
                url : "/api.php",
                type : "post",
                data : JSON.stringify(data),
                // callback handler that will be called on success
                success : function(response, textStatus, jqXHR) {
                    if (getIdentitySaltsSuccess(response)) {
                        callback();
                    } else {
                        log("ERROR", "getIdentitySalts");
                    }
                },
                // callback handler that will be called on error
                error : function(jqXHR, textStatus, errorThrown) {
                    log("ERROR", "GetIdentitySalts: The following error occured: " + textStatus);
                }
            });
            
            // getIdentitySalts on success callback.
            function getIdentitySaltsSuccess(response) {
                try {
                    // parse json
                    var result = JSON.parse(response).result;
                    if (result && result.identity
                            && result.identity.serverPasswordSalt) {
                        identity.serverPasswordSalt = result.identity.serverPasswordSalt;
                        if (result.identity.secretSalt) {
                            // set identitySecretSalt
                            identity.secretSalt = result.identity.secretSalt;
                        }
                        if (result.serverMagicValue){
                            serverMagicValue = result.serverMagicValue;
                        }
                        if (result.identity && result.identity.reloginEncryptionKey){
                            identity.reloginEncryptionKey = result.identity.reloginEncryptionKey;
                        }
                        return true;
                    } else {
                        return false;
                    }
                } catch (e) {
                    return false;
                }
            }
        };
        
        var getServerNonce = function(callback) {
            log("getServerNonce");
            var requestData = {
                "request" : {
                    "$domain" : $identityProviderDomain,
                    "$id" : generateId(),
                    "$handler" : "identity-provider",
                    "$method" : "server-nonce-get"
                }
            };
            var requestDataString = JSON.stringify(requestData);
            $.ajax({
                url : "/api.php",
                type : "post",
                data : requestDataString,
                success : function(response, textStatus, jqXHR) {
                    if (getServerNonceSuccess(response)){
                        callback();
                    } else {
                        log("ERROR", "getServerNonce");
                    }
                },
                error : function(jqXHR, textStatus, errorThrown) {
                    log("ERROR", "getServerNonce: The following error occured: "
                            + textStatus, errorThrown);
                }
            });
            
            // getServerNonceSuccess on success callback.
            function getServerNonceSuccess(response) {
                try {
                    var data = JSON.parse(response);
                    // set data to serverNonce global variable
                    identity.serverNonce = data.result.serverNonce;
                    return true;
                } catch (e) {
                    return false;
                }
            }
        };
        

        var startLoginOauth = function(){
            log("startLoginOauth");
            identity.clientAuthenticationToken = generateClientAuthenticationToken(
                generateId(), 
                generateId(),
                generateId()
            );
            var requestDataString = JSON.stringify({
                "request": {
                    "$domain": $identityProviderDomain,
                    "$appid": $appid!==undefined ? $appid : '',
                    "$id": generateId(),
                    "$handler": "identity-provider",
                    "$method": "oauth-provider-authentication",
                    "clientAuthenticationToken": identity.clientAuthenticationToken,
                    "callbackURL": identityAccessStart.browser.outerFrameURL,
                    "identity": {
                        "type": identity.type
                    }
                }
            });
            log("ajax", "/api.php", requestDataString);
            $.ajax({
                url : "/api.php",
                type : "post",
                data : requestDataString,
                // callback handler that will be called on success
                success : function(response, textStatus, jqXHR) {
                    // log a message to the console
                    log("DEBUG", "loginOAuth - on success");
                    // handle response
                    if (validateOauthProviderAuthentication(response)) {
                        log("identity", identity);
                        redirectParentOnIdentityAccessWindowResponse();
                    } else {
                        log("ERROR", "loginOAuth - validation error");
                    }
                },
                // callback handler that will be called on error
                error : function(jqXHR, textStatus, errorThrown) {
                    // log the error to the console
                    log("ERROR", "loginOAuth - on error" + textStatus);
                }
            });
            
            // loginOAuthStartScenario callback.
            function validateOauthProviderAuthentication(response) {
                try {
                    log("DEBUG", "validateOauthProviderAuthentication - response", response);
                    var responseJSON = JSON.parse(response);
                    log("DEBUG", "validateOauthProviderAuthentication - responseJSON", responseJSON);
                    var redirectURL = responseJSON.result.providerRedirectURL;
                    log("DEBUG", "validateOauthProviderAuthentication - redirectURL", redirectURL);
                    if (redirectURL){
                        identity.redirectURL = redirectURL;
                        return true;
                    }
                } catch (e) {
                    return false;
                }
                
            }
        };
        
        var redirectParentOnIdentityAccessWindowResponse = function() {
            log("redirectParentOnIdentityAccessWindowResponse");
            identityAccessWindowNotify(true);
        }
        
        var identityAccessCompleteNotify = function(data) {
            log("identityAccessCompleteNotify", data);
            log("identityAccessCompleteNotify", "identity", identity);
            var uri = generateIdentityURI(identity.type, identity.identifier);
            log("identityAccessCompleteNotify", "uri", uri);
            var lockboxkey = data.lockbox.key;
            
            // create reloginKey (only first time)
            var reloginKey = "";
            log("identityAccessCompleteNotify", "identityAccessStart", identityAccessStart);
            if (identityAccessStart.identity.reloginKey) {
                reloginKey = identityAccessStart.identity.reloginKey || "";
            } else
            if (identity.passwordStretched && identity.reloginEncryptionKey && data.identity.reloginKeyServerPart) {
                reloginKey = encrypt(identity.passwordStretched + "--" + data.identity.reloginKeyServerPart, identity.reloginEncryptionKey);
            }

            log("identityAccessCompleteNotify", "reloginKey", reloginKey);
            log("identityAccessCompleteNotify", "lockboxkey", lockboxkey);

            try {
                var message = null;
                if (lockboxkey) {
                    var iv = hash(identity.secretSalt);
                    log("identityAccessCompleteNotify", "iv", iv);
                    var key = decryptLockbox(lockboxkey, identity.passwordStretched, identity.identifier, iv);
                    log("identityAccessCompleteNotify", "key", key);
                    message = {
                        "notify": {
                            "$domain": $identityProviderDomain,
                            "$appid" : $appid,
                            "$id": generateId(),
                            "$handler": "identity",
                            "$method": "identity-access-complete",
                            
                            "identity": {
                                "accessToken": data.identity.accessToken,
                                "accessSecret": data.identity.accessSecret,
                                "accessSecretExpires": data.identity.accessSecretExpires,
                                
                                "uri": uri ,
                                "provider": $identityProviderDomain,
                                "reloginKey": reloginKey
                            },
                            "lockbox": {
                                "domain": data.$domain,
                                "key": key,
                                "reset": data.lockbox.reset
                            }
                        }
                    };
                } else {
                    message = {
                        "notify": {
                            "$domain": $identityProviderDomain,
                            "$appid" : $appid,
                            "$id": generateId(),
                            "$handler": "identity",
                            "$method": "identity-access-complete",
                            
                            "identity": {
                                "accessToken": data.identity.accessToken,
                                "accessSecret": data.identity.accessSecret,
                                "accessSecretExpires": data.identity.accessSecretExpires,
                                
                                "uri": uri,
                                "provider": $identityProviderDomain,
                                "reloginKey": reloginKey
                            }
                        }
                    };
                }

                log("identityAccessCompleteNotify", "message", message);

                return postMessage(JSON.stringify(message), "*");
            } catch(err) {
                log("ERROR", err.message, err.stack);
            }
        };
                
        var finishOAuthScenario = function(url) {
            try {
                log("finishOAuthScenario", url);
                // remove domain
                var params = url.split("?").pop();
                params = params.split("&").pop();
//                log("finishOAuthScenario", "params 1", params);
                // facebook fix (remove #...)
                params = params.split("#")[0];
//                log("finishOAuthScenario", "params 2", params);
                params = decodeURIComponent(params);

                // HACK fix for:
                // `["finishOAuthScenario","params 3 - to be JSON parsed","{\"reason\":{\"error\":\"Sign+in+failed+due+to+missing+parameter+values\"}}{\"result\":{\"loginState\":\"OAuthAuthenticationSucceeded\",\"identity\":{\"type\":\"facebook\",\"identifier\":\"100084075\"},\"serverAuthenticationToken\":\"3994743e949e5b7f2fcd4c0782135192568e5d6\"}}"]`
                var doubleJsonIndex = params.indexOf("}{");
                if (doubleJsonIndex > 0) {
                    params = params.substring(doubleJsonIndex + 1);
                }

                log("finishOAuthScenario", "params 3 - to be JSON parsed", params);
                var paramsJSON = JSON.parse(params);

                log("finishOAuthScenario", "paramsJSON", paramsJSON);

                log("get localStorage", {
                    clientAuthenticationToken: localStorage.clientAuthenticationToken,
                    identityAccessStart: localStorage.identityAccessStart,
                    $appid: localStorage.$appid
                });
                $appid = localStorage.$appid;
                if (!$appid) {
                    window.__LOGGER.setChannel("identity-provider-js-all");
                    log("finishOAuthScenario", "$appid", $appid);
                } else {
//                    window.__LOGGER.setChannel("identity-provider-js-" + $appid);
                }

                var clientAuthenticationToken = localStorage.clientAuthenticationToken;
                identityAccessStart = JSON.parse(localStorage.identityAccessStart);
                setType(identityAccessStart);
                identity.type = paramsJSON.result.identity.type;
                identity.identifier = paramsJSON.result.identity.identifier;

                log("finishOAuthScenario", "identity", identity);

                return login({
                    "request": {
                        "$domain": $identityProviderDomain,
                        "$appid" : $appid,
                        "$id": generateId(),
                        "$handler": "identity",
                        "$method": "login",                    
                        "proof" : {
                            "clientAuthenticationToken": clientAuthenticationToken,
                            "serverAuthenticationToken": paramsJSON.result.serverAuthenticationToken
                        },
                        "identity": {
                            "type": paramsJSON.result.identity.type,
                            "identifier": paramsJSON.result.identity.identifier
                        }
                    }
                });
            } catch(err) {
                if (!$appid) {
                    window.__LOGGER.setChannel("identity-provider-js-all");
                }
                log("ERROR", "finishOAuthScenario", err.message, err.stack);
            }
        };

        var login = function(loginData, loginResponseCallback) {
            log("login", loginData);
            var loginDataString = JSON.stringify(loginData);
            log("ajax", "/api.php", loginDataString);
            $.ajax({
                url : "/api.php",
                type : "post",
                data : loginDataString,
                // callback handler that will be called on success
                success : function(response, textStatus, jqXHR) {
                    log("ajax", "/api.php", "response", response);
                    try {
                        loginResponseJSON = JSON.parse(response);
                        log("login", "loginResponseJSON", loginResponseJSON);
                        if (!loginResponseJSON.result) {
                            throw new Error("No 'result' property in response");
                        }
                        if (loginResponseJSON.result.error) {
                            var err = new Error(loginResponseJSON.result.error.reason.message);
                            err.code = parseInt(loginResponseJSON.result.error.reason.$id);
                            if (loginResponseCallback) {
                                loginResponseCallback(err);
                            }
                            throw err;
                        }
                        // pin validation scenario
                        if (loginResponseJSON.result.loginState === "PinValidationRequired") {
                            pinValidateStart();
                        } else
                        if (loginResponseJSON.result.loginState === "Succeeded") {
                            // login is valid
                            // OAuth
                            if (
                                identity.type == "facebook" ||
                                identity.type == "twitter" ||
                                identity.type == "linkedin"
                            ) {
                                if (!loginResponseJSON.result.lockbox.key) {
                                    // if first time seen identity
                                    getHostingData(loginResponseJSON, true);
                                } else {
                                    // if seen this before
                                    getHostingData(loginResponseJSON, false);
                                }
                            } else {
                                // all other scenarios
                                identityAccessCompleteNotify(loginResponseJSON.result);
                            }
                        }
                    } catch(err) {
                        log("ERROR", err.message, err.stack);
                    }
                },
                // callback handler that will be called on error
                error : function(jqXHR, textStatus, errorThrown) {
                    // log the error to the console
                    log("ERROR", "login - on error" + textStatus);
                }
            });
        };

        /**
         * Generates identity URI.
         * 
         * @param type
         * @param identifier
         */
        var generateIdentityURI = function(type, identifier) {
            log("generateIdentityURI", type, identifier);
            var uri = null;
            if (type === 'facebook'){
                uri = "identity://facebook.com/" + identifier;
            }
            uri.toLowerCase();
            return uri;
        };
        
        /**
         * Identity-access-lockbox-update request.
         * 
         * @param data
         */
        var identityAccessLockboxUpdate = function(data) {
            log("identityAccessLockboxUpdate", data);
            var key = data.request.lockbox.key;
            var type = identity.type;
            var keyEncrypted = encryptLockbox(key, identity.passwordStretched, identity.identifier, identity.secretSalt);
            
            var requestData = {
                    "request": {
                        "$domain": $identityProviderDomain,
                        "$id": data.request.$id,
                        "$handler": "identity-provider",
                        "$method": "lockbox-half-key-store",
                    
                        "nonce": data.request.nonce,
                        "identity": {
                            "accessToken": data.request.identity.accessToken,
                            "accessSecretProof": data.request.identity.accessSecretProof,
                            "accessSecretProofExpires": data.request.identity.accessSecretProofExpires,
                            
                            "type": identity.type,
                            "identifier": identity.identifier,
                            "uri": data.request.identity.uri
                        },      
                        "lockbox": {
                            "keyEncrypted": keyEncrypted
                        }
                    }
            };
            
            var requestDataString = JSON.stringify(requestData);
            $.ajax({
                url : "/api.php",
                type : "post",
                data : requestDataString,
                // callback handler that will be called on success
                success : function(response, textStatus, jqXHR) {
                    if (validateIdentityAccessLockboxUpdateFedereated(response)) {
                        identityAccessLockboxUpdateResult(response);
                    } else {
                        log("ERROR", "SubmitSignup");
                    }
                },
                // callback handler that will be called on error
                error : function(jqXHR, textStatus, errorThrown) {
                    log("ERROR", "identityAccessLockboxUpdate-> The following error occured: "
                            + textStatus + errorThrown);
                }
            });
            
            function validateIdentityAccessLockboxUpdateFedereated(response){
                try {
                    var responseJSON = JSON.parse(response);
                    if (responseJSON.result.error !== undefined){
                        return true;
                    }
                    return true;
                } catch (e) {
                    return false;
                }
            }
            
        };
        
        /**
         * Identity-access-rolodex-credentials-get request.
         * 
         * @param data
         */
        var identityAccessRolodexCredentialsGet = function(data){
            log("identityAccessRolodexCredentialsGet", data);
            var requestDataString = JSON.stringify({
                "request": {
                    "$domain": $identityProviderDomain,
                    "$id": data.request.$id,
                    "$handler": data.request.$handler,
                    "$method": "identity-access-rolodex-credentials-get",
                    "clientNonce": data.request.nonce,
                    "identity": {
                        "accessToken": data.request.identity.accessToken,
                        "accessSecretProof": data.request.identity.accessSecretProof,
                        "accessSecretProofExpires": data.request.identity.accessSecretProofExpires,
                        "uri": data.request.identity.uri,
                        "provider": data.request.identity.provider
                    }
                }
            });
            $.ajax({
                url : "/api.php",
                type : "post",
                data : requestDataString,
                // callback handler that will be called on success
                success : function(response, textStatus, jqXHR) {
                    if (validateIdentityAccessRolodexCredentialsGet(response)) {
                        identityAccessRolodexCredentialsGetResult(response);
                    } else {
                        log("ERROR", "SubmitSignup");
                    }
                },
                // callback handler that will be called on error
                error : function(jqXHR, textStatus, errorThrown) {
                    log("ERROR", "identityAccessRolodexCredentialsGet-> The following error occured: "
                            + textStatus + errorThrown);
                }
            });
            
            function validateIdentityAccessRolodexCredentialsGet(response) {
                try {
                    var responseJSON = JSON.parse(response);
                    if (responseJSON.result.error !== undefined){
                        return true;
                    }
                    return true;
                } catch (e) {
                    return false;
                }
            }
            
        };
        
        var identityAccessLockboxUpdateResult = function(response) {
            log("identityAccessLockboxUpdateResult", response);
            var responseJSON = JSON.parse(response);
            var message = {
                    "result": {
                        "$domain": responseJSON.result.$domain,
                        "$appid": $appid,
                        "$id": responseJSON.result.$id,
                        "$handler": "identity",
                        "$method": "identity-access-lockbox-update",
                        "$timestamp": Math.floor(Date.now()/1000)
                      }
                    };
            postMessage(JSON.stringify(message), "*");
        };
        
        var identityAccessRolodexCredentialsGetResult = function(response) {
            log("identityAccessRolodexCredentialsGetResult", response);
            var responseJSON = JSON.parse(response);
            if (responseJSON.result.error) {
                return postMessage(JSON.stringify({
                    "result": {
                        "$domain": responseJSON.result.$domain,
                        "$appid": $appid,
                        "$id": responseJSON.result.$id,
                        "$handler": "identity",
                        "$method": "identity-access-rolodex-credentials-get",
                        // TODO: Don't sent timestamp here. Forward the one from server response.
                        "$timestamp": Math.floor(Date.now()/1000),                    
                        "error": responseJSON.result.error
                    }
                }), "*");
            }
            return postMessage(JSON.stringify({
                "result": {
                    "$domain": responseJSON.result.$domain,
                    "$appid": $appid,
                    "$id": responseJSON.result.$id,
                    "$handler": "identity",
                    "$method": "identity-access-rolodex-credentials-get",
                    // TODO: Don't sent timestamp here. Forward the one from server response.
                    "$timestamp": Math.floor(Date.now()/1000),
                    "rolodex": {
                        "serverToken": responseJSON.result.rolodex.serverToken
                    }
                }
            }), "*");
        };

        var getHostingData = function(responseJSON, setSecretScenario) {
            log("getHostingData", responseJSON, setSecretScenario);
            var reqString = JSON.stringify({
                "request": {
                    "$domain": responseJSON.result.$domain,
                    "$id": generateId(),
                    "$handler": "identity",
                    "$method": "hosting-data-get",
                    "purpose": (setSecretScenario === true) ? 
                                   "hosted-identity-secret-part-set" :
                                   "hosted-identity-secret-part-get"
                }
            });
            log("ajax", "/api.php", reqString);
            $.ajax({
                url : "/api.php",
                type : "post",
                data : reqString,
                // callback handler that will be called on success
                success: function(response, textStatus, jqXHR) {
                    try {
                        log("ajax", "/api.php", "response", response);
                        response = JSON.parse(response);
                        response.identity = responseJSON.result.identity;
                        log("ajax", "/api.php", "success", "setSecretScenario", setSecretScenario);
                        if (setSecretScenario) {
                            log("ajax", "/api.php", "success", "response", response);
                            var secretPart1 = generateSecretPart(generateId(), response.identity.accessToken);
                            log("ajax", "/api.php", "success", "secretPart1", secretPart1);
                            var secretPart2 = generateSecretPart(generateId(), response.identity.accessSecret);
                            log("ajax", "/api.php", "success", "secretPart2", secretPart2);
                            hostedIdentitySecretSet(response, secretPart1, passwordServer1);
                            hostedIdentitySecretSet(response, secretPart2, passwordServer2);
                        } else {
                            hostedIdentitySecretGet(response, passwordServer1);
                            hostedIdentitySecretGet(response, passwordServer2);
                        }
                    } catch(err) {
                        log("ERROR", err.message, err.stack);
                    }
                },
                // callback handler that will be called on error
                error: function(jqXHR, textStatus, errorThrown) {
                    log("ERROR", "getHostingData", textStatus);
                }
            });
        };

        var hostedIdentitySecretSet = function(responseJSON, secretPart, server) {
            log("hostedIdentitySecretSet", responseJSON, secretPart, server);
            var nonce = responseJSON.result.hostingData.nonce;
            log("hostedIdentitySecretSet", "nonce", nonce);
            var hostingProof = responseJSON.result.hostingData.hostingProof;
            log("hostedIdentitySecretSet", "hostingProof", hostingProof);
            var hostingProofExpires = responseJSON.result.hostingData.hostingProofExpires;
            var clientNonce = generateId();
            log("hostedIdentitySecretSet", "identity", identity);
            var uri = generateIdentityURI(identity.type, identity.identifier);
            log("hostedIdentitySecretSet", "uri", uri);
            var accessSecretProof = generateAccessSecretProof(
                uri,
                clientNonce,
                responseJSON.identity.accessSecretExpires,
                responseJSON.identity.accessToken,
                "hosted-identity-secret-part-set",
                responseJSON.identity.accessSecret
            );
            log("hostedIdentitySecretSet", "accessSecretProof", accessSecretProof);
            var accessSecretProofExpires = responseJSON.identity.accessSecretExpires;
            log("hostedIdentitySecretSet", "accessSecretProofExpires", accessSecretProofExpires);
            // generate secretSalt
            var identitySecretSalt = generateSecretSaltForArgs([
                identity.identifier,
                nonce,
                clientNonce,
                generateId()
            ]);
            log("hostedIdentitySecretSet", "identitySecretSalt", identitySecretSalt);
            var reqString = JSON.stringify({
                "request": {
                    "$domain": responseJSON.result.$domain,
                    "$id": generateId(),
                    "$handler": "identity",
                    "$method": "hosted-identity-secret-part-set",
                    "nonce": nonce,
                    "hostingProof": hostingProof,
                    "hostingProofExpires": hostingProofExpires,
                    "clientNonce": clientNonce,
                    "identity": {
                        "accessToken": responseJSON.identity.accessToken,
                        "accessSecretProof": accessSecretProof,
                        "accessSecretProofExpires": accessSecretProofExpires,                        
                        "uri": uri,
                        "secretSalt": identitySecretSalt,
                        "secretPart": secretPart
                    }
                }
            });
            log("ajax", server, reqString);
            $.ajax({
                url : server,
                type : "post",
                data : reqString,
                dataType: "json",
                contentType: "application/json",
                // callback handler that will be called on success
                success: function(response, textStatus, jqXHR) {
                    log("ajax", server, "response", response);
                    return afterSecretSet(response, secretPart);
                },
                // callback handler that will be called on error
                error: function(jqXHR, textStatus, errorThrown) {
                    log("ERROR", "hostedIdentitySecretSet", textStatus, errorThrown, {
                        readyState: jqXHR.readyState,
                        status: jqXHR.status,
                        statusText: jqXHR.statusText,
                        responseText: jqXHR.responseText
                    });
                }
            });
        };

        var afterSecretSet = function(dataJSON, secretPart) {
            log("afterSecretSet", dataJSON, secretPart);
            try {
                log("afterSecretSet", identity);
                if (identity.secretPartSet === undefined) {
                    log("afterSecretSet", "if branch", secretSetResults);
                    identity.secretPartSet = secretPart;
                } else {
                    log("afterSecretSet", "else branch", secretSetResults);
                    identity.passwordStretched = xorEncode(identity.secretPartSet, secretPart);
                }
                log("afterSecretSet", secretSetResults, identity);
                
                if (!dataJSON.result.error) {
                    secretSetResults++;
                }
                if (secretSetResults === 2) {
                    log("afterSecreySet", "Will enter identityAccessCompleteNotify with loginResponseJSON:", loginResponseJSON);
                    identityAccessCompleteNotify(loginResponseJSON.result);
                }
            } catch(err) {
                log("ERROR", err.message, err.stack);
            }
        };

        var hostedIdentitySecretGet = function(data, server) {
            log("hostedIdentitySecretSet", data, server);
            var nonce = data.result.hostingData.nonce;
            log("hostedIdentitySecretSet", "nonce", nonce);
            var hostingProof = data.result.hostingData.hostingProof;
            log("hostedIdentitySecretSet", "hostingProof", hostingProof);
            var hostingProofExpires = data.result.hostingData.hostingProofExpires;
            var clientNonce = generateId();
            log("hostedIdentitySecretSet", "identity", identity);
            var uri = generateIdentityURI(identity.type, identity.identifier);
            log("hostedIdentitySecretSet", "uri", uri);
            var accessSecretProof = generateAccessSecretProof(
                uri,
                clientNonce,
                data.identity.accessSecretExpires,
                data.identity.accessToken,
                "hosted-identity-secret-part-get",
                data.identity.accessSecret
            );
            log("hostedIdentitySecretSet", "accessSecretProof", accessSecretProof);
            var accessSecretProofExpires = data.identity.accessSecretExpires;
            log("hostedIdentitySecretSet", "accessSecretProofExpires", accessSecretProofExpires);
            // hosted-identity-secret-get scenario
            var reqString = JSON.stringify({
                "request": {
                    "$domain": data.result.$domain,
                    "$id": generateId(),
                    "$handler": "identity",
                    "$method": "hosted-identity-secret-part-get",
                    "nonce": nonce,
                    "hostingProof": hostingProof,
                    "hostingProofExpires": hostingProofExpires,
                    "clientNonce": clientNonce,
                    "identity": {
                        "accessToken": data.identity.accessToken,
                        "accessSecretProof": accessSecretProof,
                        "accessSecretProofExpires": accessSecretProofExpires,                        
                        "uri": uri
                    }
                }
            });
            log("ajax", server, reqString);
            $.ajax({
                url : server,
                type : "post",
                data : reqString,
                dataType: "json",
                contentType: "application/json",
                // callback handler that will be called on success
                success : function(response, textStatus, jqXHR) {
                    log("ajax", "/api.php", "response", response);
                    // handle response
                    afterSecretGet(response);
                },
                // callback handler that will be called on error
                error : function(jqXHR, textStatus, errorThrown) {
                    log("ERROR", "hostedIdentitySecretGet", textStatus, errorThrown, {
                        readyState: jqXHR.readyState,
                        status: jqXHR.status,
                        statusText: jqXHR.statusText,
                        responseText: jqXHR.responseText
                    });
                }
            });
            var afterSecretGet = function(response) {
                try {
                    log("afterSecretGet", response);
                    log("afterSecretGet", "identity", identity);
                    log("afterSecretGet", "loginResponseJSON", loginResponseJSON);
                    if (response.result.error) {
                        log("ERROR", response.result.error);
                        return;
                    }
                    if (!identity.secretPart) {
                        identity.secretPart = response.result.identity.secretPart;
                    } else {
                        identity.passwordStretched = xorEncode(identity.secretPart, response.result.identity.secretPart);
                        delete identity.secretPart;
                        identity.secretSalt = response.result.identity.secretSalt;
                    }
                    secretGetResults++;
                    if (secretGetResults === 2) {
                        log("afterSecretGet", "identity after", identity);
                        identityAccessCompleteNotify(loginResponseJSON.result);
                    }
                } catch(err) {
                    log("ERROR", err.message, err.stack);
                }
            }
        };
        
        return {
            init : init,
            showView: showView
        };
    };

    ////////////// OTHER STUFF ///////////////////

    // startsWith method definition
    if (typeof String.prototype.startsWith != 'function') {
        String.prototype.startsWith = function(str) {
            return this.indexOf(str) == 0;
        };
    }

    // /////////////////////////////////////////////////////////
    // generate methods
    // /////////////////////////////////////////////////////////

    // Generates secret.
    //
    // @param p1
    // @param p2
    //
    // @return secret
    function generateSecretPart(p1, p2) {
        log("generateSecretPart", p1, p2);
        var sha1 = CryptoJS.algo.SHA1.create();
        // add entropy
        sha1.update(p1);
        sha1.update(p2);
        var secret = sha1.finalize();
        log("generateSecretPart", "secret", secret);
        return secret.toString();
    }

    
    // Generates secretAccessSecretProof
    // 
    // @param uri 
    // @param clientNonce 
    // @param accessSecretExpires 
    // @param accessToken 
    // @param purpose 
    // @param accessSecret 
    // 
    // @return accessSecretProof
    function generateAccessSecretProof(
            uri,
            clientNonce,
            accessSecretExpires,
            accessToken,
            purpose,
            accessSecret) {
        var message = 'identity-access-validate:' + uri + ':' + clientNonce + ':' + accessSecretExpires + ':' + accessToken + ':' + purpose;
        return hmac(message, accessSecret);
    }

    String.prototype.toHex = function() {
        var hex = '', tmp;
        for(var i=0; i<this.length; i++) {
            tmp = this.charCodeAt(i).toString(16)
            if (tmp.length == 1) {
                tmp = '0' + tmp;
            }
            hex += tmp
        }
        return hex;
    }

    String.prototype.xor = function(other)
    {
        var xor = "";
        for (var i = 0; i < this.length && i < other.length; ++i) {
            xor += String.fromCharCode(this.charCodeAt(i) ^ other.charCodeAt(i));
        }
        return xor;
    }
    function xorEncode(txt1, txt2) {
        var ord = [];
        var buf = "";
        for (z = 1; z <= 255; z++) {
            ord[String.fromCharCode(z)] = z;
        }
        for (j = z = 0; z < txt1.length; z++) {
            buf += String.fromCharCode(ord[txt1.substr(z, 1)] ^ ord[txt2.substr(j, 1)]);
            j = (j < txt2.length) ? j + 1 : 0;
        }
        return buf;
    }

    // Generates passwordStretched.
    //
    // @param identity
    // @param password
    // @param serverPasswordSalt
    // @return passwordStreched
    function generatePasswordStretched(identifier, password, serverPasswordSalt) {
        var passwordStretched = "password-hash:" + identifier + password
                + serverPasswordSalt;
        // key stretching
        // @see http://en.wikipedia.org/wiki/Key_stretching
        for ( var i = 0; i < 128; i++) {
            passwordStretched = hash(passwordStretched);
        }
        return passwordStretched;
    }

    // Generates IdentitySecretSalt.
    //
    // @param clientToken
    // @param serverToken
    // @param clientLoginSecretHash
    // @param serverSalt
    // @return IdentitySecretSalt
    function generateIdentitySecretSalt(clientToken, serverToken, clientLoginSecretHash, serverSalt) {
        var secretSalt;
        var sha1 = CryptoJS.algo.SHA1.create();
        // add entropy
        sha1.update(clientToken);
        sha1.update(serverToken);
        sha1.update(clientLoginSecretHash);
        sha1.update(serverSalt);
        secretSalt = sha1.finalize();

        return secretSalt.toString();
    }

    function generateSecretSaltForArgs(args) {
        log("generateSecretSaltForArgs", args);
        var sha1 = CryptoJS.algo.SHA1.create();
        args.forEach(function(arg) {
            sha1.update(arg);
        });
        return sha1.finalize().toString();
    }

    // Generates serverLoginProof.
    //
    // @param serverMagicValue
    // @param passwordStretched
    // @param identifier
    // @param serverPasswordSalt
    // @param identitySecretSalt
    // @return serverLoginProof
    function generateServerLoginProof(serverMagicValue, 
                                      passwordStretched, 
                                      identifier,
                                      serverPasswordSalt,
                                      identitySecretSalt) {
        var serverLoginProofInnerHmac = hmac('password-hash:' + identifier +':' + base64(serverPasswordSalt), 
                                              passwordStretched);
        var identitySaltHash = hash('salt:' + identifier + ':' + base64(identitySecretSalt));
        return hash(serverMagicValue + ':' + serverLoginProofInnerHmac + ':' + identitySaltHash);
    }

    // Generates serverLoginFinalProof.
    //
    // @param serverMagicValue
    // @param serverLoginProof
    // @param serverNonce
    // @return serverLoginFinalProof
    function generateServerLoginFinalProof(serverMagicValue, 
                                           serverLoginProof,     
                                           serverNonce) {
        return hmac('final:' + serverLoginProof + ':' + serverNonce, serverMagicValue);
    }

    function generateClientAuthenticationToken (random1, random2, random3) {
        var sha1 = CryptoJS.algo.SHA1.create();
        sha1.update(random1 + "d");
        sha1.update(random2 + "d");
        sha1.update(random3 + "d");
        return sha1.finalize().toString();
    }

    // ADAPTER METHODS

    // base64 encoder.
    //
    // @param input
    // @return base64 encoded
    function base64(input) {
        return Base64.encode(input);
    }

    // SHA1 hash method.
    //
    // @param input
    // @return hash
    function hash(input) {
        return CryptoJS.SHA1(input).toString();
    }

    // HmacSHA1.
    //
    // @param message
    // @param key
    // @return HmacSHA1
    function hmac(message, key) {
        return CryptoJS.HmacSHA1(message, key).toString();
    }

    // AES encrypt method
    //
    // @param message
    // @param key
    // @param iv
    // @return encrypted
    function encrypt(message, key, iv) {
        if (iv) {
            return CryptoJS.AES.encrypt(message, key, {
                iv : iv
            }).toString();
        } else {
            return CryptoJS.AES.encrypt(message, key).toString();
        }

    }

    //AES decrypt method
    //
    // @param message
    // @param key
    // @param iv
    // @return encrypted
    function decrypt(message, key, iv) {
        if (iv) {
            return CryptoJS.AES.decrypt(message, key, {
                iv : iv
            }).toString(CryptoJS.enc.Utf8);
        } else {
            return CryptoJS.AES.decrypt(message, key).toString(CryptoJS.enc.Utf8);
        }
    }

})(window);
