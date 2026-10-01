// SSL Pinning Bypass + Network Interceptor for APEX-X
// Hooks TrustManager, OkHttp, HttpURLConnection, and WebView SSL
// to bypass certificate pinning and capture all HTTP(S) traffic.

Java.perform(function() {
    var TAG = "[APEX-X]";
    
    // ═══════════════════════════════════════════════════════════
    // 1. SSL PINNING BYPASS — TrustManager
    // ═══════════════════════════════════════════════════════════
    
    try {
        var TrustManager = Java.registerClass({
            name: "com.apexx.TrustManager",
            implements: [Java.use("javax.net.ssl.X509TrustManager")],
            methods: {
                checkClientTrusted: function(chain, authType) { },
                checkServerTrusted: function(chain, authType) { },
                getAcceptedIssuers: function() { return []; }
            }
        });

        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        var sslInit = SSLContext.init.overload(
            "[Ljavax.net.ssl.KeyManager;",
            "[Ljavax.net.ssl.TrustManager;",
            "java.security.SecureRandom"
        );
        sslInit.implementation = function(km, tm, sr) {
            var trustAll = Java.array("javax.net.ssl.TrustManager", [TrustManager.$new()]);
            sslInit.call(this, km, trustAll, sr);
            send({type: "ssl_bypass", detail: "SSLContext.init patched"});
        };
    } catch(e) { /* SSLContext hook failed — may not be used */ }

    // ═══════════════════════════════════════════════════════════
    // 2. SSL PINNING BYPASS — OkHttp3 CertificatePinner
    // ═══════════════════════════════════════════════════════════
    
    try {
        var CertPinner = Java.use("okhttp3.CertificatePinner");
        CertPinner.check.overload("java.lang.String", "java.util.List").implementation = function(hostname, peerCerts) {
            send({type: "ssl_bypass", detail: "OkHttp3 CertificatePinner bypassed for: " + hostname});
        };
    } catch(e) { /* OkHttp3 not present */ }

    try {
        var CertPinner2 = Java.use("okhttp3.CertificatePinner");
        CertPinner2["check$okhttp"].implementation = function(hostname, fn) {
            send({type: "ssl_bypass", detail: "OkHttp3 check$okhttp bypassed for: " + hostname});
        };
    } catch(e) { /* Older OkHttp format not present */ }

    // ═══════════════════════════════════════════════════════════
    // 3. SSL PINNING BYPASS — WebViewClient
    // ═══════════════════════════════════════════════════════════
    
    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.onReceivedSslError.overload(
            "android.webkit.WebView",
            "android.webkit.SslErrorHandler",
            "android.net.http.SslError"
        ).implementation = function(view, handler, error) {
            handler.proceed();
            send({type: "ssl_bypass", detail: "WebView SSL error ignored"});
        };
    } catch(e) { /* WebViewClient hook failed */ }

    // ═══════════════════════════════════════════════════════════
    // 4. NETWORK INTERCEPTOR — HttpURLConnection
    // ═══════════════════════════════════════════════════════════
    
    try {
        var URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function() {
            var conn = this.openConnection();
            var url = this.toString();
            send({
                type: "network",
                subtype: "url_connection",
                url: url,
                method: "GET",
                timestamp: Date.now()
            });
            return conn;
        };
    } catch(e) { /* URL.openConnection hook failed */ }

    // ═══════════════════════════════════════════════════════════
    // 5. NETWORK INTERCEPTOR — OkHttp3 Requests
    // ═══════════════════════════════════════════════════════════
    
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        var RealCall = Java.use("okhttp3.internal.connection.RealCall");

        RealCall.execute.implementation = function() {
            var request = this.request();
            var url = request.url().toString();
            var method = request.method();
            var headers = {};
            var headerNames = request.headers();
            
            try {
                for (var i = 0; i < headerNames.size(); i++) {
                    headers[headerNames.name(i)] = headerNames.value(i);
                }
            } catch(e) {}

            var bodyStr = "";
            try {
                var body = request.body();
                if (body !== null) {
                    var Buffer = Java.use("okio.Buffer");
                    var buf = Buffer.$new();
                    body.writeTo(buf);
                    bodyStr = buf.readUtf8();
                    if (bodyStr.length > 4096) bodyStr = bodyStr.substring(0, 4096) + "...[truncated]";
                }
            } catch(e) {}

            send({
                type: "network",
                subtype: "okhttp_request",
                url: url,
                method: method,
                headers: headers,
                body: bodyStr,
                timestamp: Date.now()
            });

            var response = this.execute();
            
            try {
                send({
                    type: "network",
                    subtype: "okhttp_response",
                    url: url,
                    status: response.code(),
                    content_type: response.header("Content-Type") || "",
                    content_length: response.header("Content-Length") || "unknown",
                    timestamp: Date.now()
                });
            } catch(e) {}

            return response;
        };
    } catch(e) { /* OkHttp RealCall hook failed */ }

    // ═══════════════════════════════════════════════════════════
    // 6. NETWORK INTERCEPTOR — Socket.connect (raw TCP)
    // ═══════════════════════════════════════════════════════════
    
    try {
        var Socket = Java.use("java.net.Socket");
        Socket.connect.overload("java.net.SocketAddress", "int").implementation = function(addr, timeout) {
            var dest = addr.toString();
            send({
                type: "network",
                subtype: "socket_connect",
                destination: dest,
                timestamp: Date.now()
            });
            this.connect(addr, timeout);
        };
    } catch(e) { /* Socket hook failed */ }

    // ═══════════════════════════════════════════════════════════
    // 7. DNS RESOLVER — Capture DNS lookups
    // ═══════════════════════════════════════════════════════════
    
    try {
        var InetAddress = Java.use("java.net.InetAddress");
        InetAddress.getByName.overload("java.lang.String").implementation = function(host) {
            var result = this.getByName(host);
            send({
                type: "dns",
                hostname: host,
                resolved_ip: result.getHostAddress(),
                timestamp: Date.now()
            });
            return result;
        };
    } catch(e) { /* InetAddress hook failed */ }

    send({type: "status", detail: "SSL bypass + Network hooks loaded successfully"});
});
