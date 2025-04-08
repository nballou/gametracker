'use strict';

Java.perform(function() {
    console.log("[*] Network Intercept Script Loaded");

    // Enumerate loaded classes containing "okhttp3"
    console.log("[*] Enumerating classes for OkHttp:");
    Java.enumerateLoadedClasses({
        onMatch: function(name) {
            if (name.indexOf("okhttp3") !== -1) {
                console.log("   " + name);
            }
        },
        onComplete: function() {
            console.log("[*] Done enumerating OkHttp classes.");
        }
    });

    // Attempt to hook HttpsURLConnection.getInputStream()
    try {
        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        console.log("[*] Hooking HttpsURLConnection.getInputStream()");
        HttpsURLConnection.getInputStream.implementation = function() {
            console.log("[*] HttpsURLConnection.getInputStream() called for URL: " + this.getURL().toString());
            var origStream = this.getInputStream();
            var ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
            var ByteArrayInputStream = Java.use("java.io.ByteArrayInputStream");
            var StringClass = Java.use("java.lang.String");

            var bos = ByteArrayOutputStream.$new();
            var buffer = Java.array('byte', new Array(1024).fill(0));
            var len = 0;
            try {
                while ((len = origStream.read(buffer, 0, buffer.length)) != -1) {
                    bos.write(buffer, 0, len);
                }
            } catch(e) {
                console.error("[*] Error reading HttpsURLConnection InputStream: " + e);
                return origStream;
            }
            var data = bos.toByteArray();
            var response = "";
            try {
                response = StringClass.$new(data, "UTF-8");
            } catch(e) {
                console.error("[*] Error converting response to string: " + e);
            }
            console.log("[*] HttpsURLConnection response for URL " + this.getURL().toString() + ":");
            console.log(response);

            // Rebuild the InputStream so the app can continue reading normally.
            var newStream = ByteArrayInputStream.$new(data);
            return newStream;
        };
    } catch(e) {
        console.error("[*] HttpsURLConnection hook error: " + e);
    }

    // Attempt to hook com.android.org.conscrypt.OpenSSLSocketImpl.getInputStream()
    try {
        var OpenSSLSocketImpl = Java.use("com.android.org.conscrypt.OpenSSLSocketImpl");
        console.log("[*] Hooking OpenSSLSocketImpl.getInputStream()");
        OpenSSLSocketImpl.getInputStream.implementation = function() {
            console.log("[*] OpenSSLSocketImpl.getInputStream() called");
            var origStream = this.getInputStream();
            var ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
            var ByteArrayInputStream = Java.use("java.io.ByteArrayInputStream");
            var StringClass = Java.use("java.lang.String");

            var bos = ByteArrayOutputStream.$new();
            var buffer = Java.array('byte', new Array(1024).fill(0));
            var len = 0;
            try {
                while ((len = origStream.read(buffer, 0, buffer.length)) != -1) {
                    bos.write(buffer, 0, len);
                }
            } catch(e) {
                console.error("[*] Error reading OpenSSLSocketImpl InputStream: " + e);
                return origStream;
            }
            var data = bos.toByteArray();
            var response = "";
            try {
                response = StringClass.$new(data, "UTF-8");
            } catch(e) {
                console.error("[*] Error converting OpenSSLSocketImpl response to string: " + e);
            }
            console.log("[*] OpenSSLSocketImpl response:");
            console.log(response);

            var newStream = ByteArrayInputStream.$new(data);
            return newStream;
        };
    } catch(e) {
        console.error("[*] OpenSSLSocketImpl hook error: " + e);
    }
});
