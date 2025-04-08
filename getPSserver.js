var getServerName = Module.findExportByName("libssl.so", "SSL_get_servername");
if (getServerName) {
    Interceptor.attach(getServerName, {
        onEnter: function(args) {
            // nothing to do on enter
        },
        onLeave: function(retval) {
            if (!retval.isNull()) {
                var serverName = Memory.readUtf8String(retval);
                console.log("Server name (SNI) is: " + serverName);
            }
        }
    });
    console.log("Hooked SSL_get_servername at: " + getServerName);
} else {
    console.log("Could not find SSL_get_servername");
}
