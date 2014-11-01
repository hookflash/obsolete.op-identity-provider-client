
<html>
<head>
<title>Example Identity Provider</title>

<style>
HTML, BODY, DIV.op-centered {
    border-image: none;
    background-color: #{{ config.CONFIG_loginBackgroundColor }};
}
</style>

<link rel="stylesheet" href="{{ config.ASSET_PATH }}/style-oauth.css"/>

<style>
HTML, BODY, DIV.op-centered {
    border-image: none;
    background-color: #{{ config.CONFIG_loginBackgroundColor }};
}
</style>

<script type="text/javascript" src="//{{ config.HF_LOGGER_HOST }}/tools/logger/logger.js"></script>
<script type="text/javascript" src="{{ config.ASSET_PATH }}/js/lib/cryptojs/rollups/sha1.js"></script>
<script type="text/javascript" src="{{ config.ASSET_PATH }}/js/lib/jquery/jquery-1.8.3.min.js"></script>
<script type="text/javascript" src="{{ config.ASSET_PATH }}/js/HF-oauth.js"></script>

<script type="text/javascript">

    window.__LOGGER.setUrl("//{{ config.HF_LOGGER_HOST }}/tools/logger/record");
    window.__LOGGER.setChannel("identity-provider-js-all");

    $(document).ready(function() {
        window._HCS_IDENTITY_PROVIDER({
            // TODO: Don't use `document.domain` here. Should use config variable instead.
            domain: document.domain,
            configuredServices: {{ config.HF_CONFIGURED_SERVICES }}
        });        
    });
</script>
</head>

<body>
    <div class="op-centered">
        <div id="op-spinner"></div>

        <div id="op-service-oauth-view" class="view op-hidden">
            <div class="op-view">
                <button id="op-social-oauth-button">Login using configured oAuth server</button>
            </div>
        </div>

        <div id="op-service-facebook_v1-view" class="view op-hidden">
            <div class="op-view">
                <button id="op-service-facebook_v1-button"><img src="{{ config.ASSET_PATH }}/images/iPhone_signin_facebook@2x.png"></button>
            </div>
        </div>

        <div id="op-service-facebook-view" class="view op-hidden">
            <div class="op-view">
                <button id="op-service-facebook-button"><img src="{{ config.ASSET_PATH }}/images/iPhone_signin_facebook@2x.png"> v2</button>
            </div>
        </div>

        <div id="op-service-twitter-view" class="view op-hidden">
            <div class="op-view">
                <button id="op-service-twitter-button"><img src="{{ config.ASSET_PATH }}/images/sign-in-with-twitter-gray.png"></button>
            </div>
        </div>

        <div id="op-service-none-view" class="view op-hidden">
            <div class="op-view">
                Configuration Error: No identity service configured for this identity provider!
            </div>
        </div>

    </div>
</body>
</html>

