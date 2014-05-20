<!-- 

Copyright (c) 2012, SMB Phone Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The views and conclusions contained in the software and documentation are those
of the authors and should not be interpreted as representing official policies,
either expressed or implied, of the FreeBSD Project.

 -->

<!--
  Example Identity Provider Login page.
-->

<html>
<head>
<title>Example Identity Provider - Login/Sign up</title>

<script type="text/javascript" src="//{{ config.HF_LOGGER_HOST }}/tools/logger/logger.js"></script>

<script type="text/javascript" src="{{ config.ASSET_PATH }}js/lib/cryptojs/rollups/sha1.js"></script>
<script type="text/javascript" src="{{ config.ASSET_PATH }}js/lib/cryptojs/rollups/sha256.js"></script>
<script type="text/javascript" src="{{ config.ASSET_PATH }}js/lib/cryptojs/rollups/hmac-sha1.js"></script>
<script type="text/javascript" src="{{ config.ASSET_PATH }}js/lib/cryptojs/rollups/aes.js"></script>
<script type="text/javascript" src="{{ config.ASSET_PATH }}js/lib/jquery/jquery-1.8.3.min.js"></script>
<script type="text/javascript" src="{{ config.ASSET_PATH }}js/lib/ajaxfileupload.js"></script>
<script type="text/javascript" src="{{ config.ASSET_PATH }}js/lib/base64.js"></script>
<script type="text/javascript" src="{{ config.ASSET_PATH }}js/lib/q.js"></script>
<!--
<script type="text/javascript" src="{{ config.ASSET_PATH }}js/lib/cifre/aes.js"></script>
<script type="text/javascript" src="{{ config.ASSET_PATH }}js/lib/cifre/utils.js"></script>
-->
<script type="text/javascript" src="{{ config.ASSET_PATH }}js/HF.js"></script>

<link rel="stylesheet" href="{{ config.ASSET_PATH }}style.css"/>

<script type="text/javascript">

    window.__LOGGER.setUrl("//{{ config.HF_LOGGER_HOST }}/tools/logger/record");
    window.__LOGGER.setChannel("identity-provider-js-all");

    var HF = new HF_LoginAPI();

    $(document).ready(function() {
        
        if (/dev=true/.test(window.location.search)) {
            $("HEAD").append('<link rel="stylesheet" href="{{ config.ASSET_PATH }}style-dev.css"/>');
            $("BODY").prepend('<div class="op-view-label">' + window.location.pathname + '</div>');
        }

        HF.init({
            identityServiceAuthenticationURL: "{{ config.SESSION_identityServiceAuthenticationURL }}",
            // TODO: Don't use `document.domain` here. Should use config variable instead.
            $identityProvider: document.domain,
            passwordServer1: "{{ config.HF_PASSWORD1_BASEURI }}",
            passwordServer2: "{{ config.HF_PASSWORD2_BASEURI }}",
            login: {
                click: "loginClick",
                id: "loginId",
                password: "loginPassword"
            },
            signup: {   
                click: "signupClick",
                id: "signUpId",
                password: "signUpPassword",
                displayName: "signUpDisplayName"
            },
            pinClick: "pinClick",
            ignoreBase: {{ config.IGNORE_BASE }},
            hideCustom: {{ config.HIDE_CUSTOM }}
        });        
    });

    window.addEventListener("message", function (event) {
        try {
            var message = JSON.parse(event.data);
            var regInfo = message._test_register;
            var loginInfo = message._test_login;
            if(regInfo) {
                var regInfo = message._test_register;
                doRegister(regInfo.name, regInfo.username, regInfo.password);
            } else if(loginInfo) {
                var loginInfo = message._test_login;
                doLogin(loginInfo.username, loginInfo.password);
            }
        } catch(e) {
            console.error('test-ui-login-error', e.message);
            throw e;
        }
    }, false);

    function doRegister(name, username, password) {
        HF.showView('custom-signup');
        $('#signUpDisplayName').val(name);
        $('#signUpId').val(username);
        $('#signUpPassword').val(password);
        $('#op-custom-signup-button').click()
    }

    function doLogin(username, password){
        HF.showView('custom-login');
        $('#loginId').val(username);
        $('#loginPassword').val(password);
        $('#op-custom-login-button').click();
    }
</script>
</head>

<body>
    <div class="op-centered">
        <div id="op-logo"></div>
        <div id="op-spinner"></div>
        <div id="op-custom-login-view" class="op-hidden">
            <div class="op-view">
                <h1>Login</h1>
                <div class="op-error op-hidden"></div>
                <div class="op-fieldset"><input type="text" id="loginId" placeholder="username" autocorrect="off" autocapitalize="off"/></div>
                <div class="op-fieldset"><input type="password" id="loginPassword" placeholder="password" autocorrect="off" autocapitalize="off"/></div>
                <div class="op-fieldset">
                    <button id="op-custom-login-button">Login</button>
                    <div class="op-fieldset-actions"><a class="op-buttonlink" href="#" onclick="HF.showView('custom-signup');">Sign Up</a></div>
                </div>
            </div>
        </div>

        <div id="op-custom-signup-view" class="op-hidden">
            <div class="op-view">
                <h1>Create Account</h1>

                <div class="op-headerlink"><a class="op-headerlink" href="#" onclick="HF.showView('custom-login');">Back</a></div>

                <div class="op-error op-hidden"></div>
<!--                
                <div class="op-fieldset"><label>Avatar</label><input type="file" name="file" id="file" /><button id="op-custom-signup-upload-button">Upload</button></div>
-->
                <div class="op-fieldset"><label>Display Name</label><input type="text" id="signUpDisplayName" autocorrect="off" autocapitalize="off"/></div>
                <div class="op-fieldset"><label>Username</label><input type="text" id="signUpId" autocorrect="off" autocapitalize="off"/></div>
                <div class="op-fieldset"><label>Password</label><input type="password" id="signUpPassword" autocorrect="off" autocapitalize="off"/></div>
                <div class="op-fieldset">
                    <button id="op-custom-signup-button">Sign up</button>
                    <div class="op-fieldset-actions"><a class="op-buttonlink" href="#" onclick="HF.showView('custom-login');">Log In</a></div>
                </div>
            </div>
        </div>

        <div id="op-social-facebook-view" class="op-hidden">
            <div class="op-view">
                <button id="op-social-facebook-button"><img src="{{ config.ASSET_PATH }}images/iPhone_signin_facebook@2x.png"></button>
            </div>
        </div>

        <div id="op-pinvalidation-view" class="op-hidden">
            <div class="op-view">
                <h1>Enter PIN</h1>
                <input type="text" size="6" id="pin" autocorrect="off" autocapitalize="off"/>
                <button onclick="op-pinvalidation-button" >Validate PIN</button>
                <div id="pinexpired">&nbps;</div>
            </div>
        </div>
    </div>
</body>
</html>

