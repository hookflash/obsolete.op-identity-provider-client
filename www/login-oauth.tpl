
<html>
<head>
<title>Example Identity Provider</title>

<link rel="stylesheet" href="{{ config.ASSET_PATH }}/style-oauth.css"/>

<script type="text/javascript" src="//{{ config.HF_LOGGER_HOST }}/tools/logger/logger.js"></script>

<script type="text/javascript" src="{{ config.ASSET_PATH }}/js/lib/cryptojs/rollups/sha1.js"></script>
<script type="text/javascript" src="{{ config.ASSET_PATH }}/js/lib/cryptojs/rollups/sha256.js"></script>
<script type="text/javascript" src="{{ config.ASSET_PATH }}/js/lib/cryptojs/rollups/hmac-sha1.js"></script>
<script type="text/javascript" src="{{ config.ASSET_PATH }}/js/lib/cryptojs/rollups/aes.js"></script>
<script type="text/javascript" src="{{ config.ASSET_PATH }}/js/lib/jquery/jquery-1.8.3.min.js"></script>
<script type="text/javascript" src="{{ config.ASSET_PATH }}/js/lib/ajaxfileupload.js"></script>
<script type="text/javascript" src="{{ config.ASSET_PATH }}/js/lib/base64.js"></script>
<script type="text/javascript" src="{{ config.ASSET_PATH }}/js/lib/q.js"></script>
<script type="text/javascript" src="{{ config.ASSET_PATH }}/js/HF-oauth.js"></script>

<script type="text/javascript">

    window.__LOGGER.setUrl("//{{ config.HF_LOGGER_HOST }}/tools/logger/record");
    window.__LOGGER.setChannel("identity-provider-js-all");

    var HF = new HF_LoginAPI();

    $(document).ready(function() {
        HF.init({
            identityServiceAuthenticationURL: "{{ config.SESSION_identityServiceAuthenticationURL }}",
            // TODO: Don't use `document.domain` here. Should use config variable instead.
            $identityProvider: document.domain,
            passwordServer1: "{{ config.HF_PASSWORD1_BASEURI }}",
            passwordServer2: "{{ config.HF_PASSWORD2_BASEURI }}"
        });        
    });
</script>
</head>

<body>
    <div class="op-centered">
        <div id="op-spinner"></div>

        <div id="op-service-oauth-view" class="op-hidden">
            <div class="op-view">
                <button id="op-social-oauth-button">Login using configured oAuth server</button>
            </div>
        </div>

        <div id="op-service-facebook-view" class="op-hidden">
            <div class="op-view">
                <button id="op-service-facebook-button"><img src="{{ config.ASSET_PATH }}/images/iPhone_signin_facebook@2x.png"></button>
            </div>
        </div>

    </div>
</body>
</html>

