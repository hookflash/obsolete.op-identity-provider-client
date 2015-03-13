<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <script src="http://{{ config.HCS_API_DEV_HOST }}/lib/pinf-loader-js/loader.js"></script>
    <script>
        PINF.sandbox("http://{{ config.HCS_API_DEV_HOST }}/client-frame-inner.js", function (sandbox) {
            sandbox.main();
        }, function (err) {
            console.error("Error while loading bundle 'http://{{ config.HCS_API_DEV_HOST }}/client-frame-inner.js':", err.stack);
        });
    </script>    
</head>

<body>

</body>

</html>
