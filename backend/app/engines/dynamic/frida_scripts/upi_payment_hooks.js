// UPI & Payment Data Capture Hooks for APEX-X
// Monitors UPI SDK interactions, EditText input capture,
// and payment-related intent/broadcast activity.

Java.perform(function() {
    var TAG = "[APEX-X-UPI]";

    // ═══════════════════════════════════════════════════════════
    // 1. EditText Input Capture — Detects PIN/OTP/credential theft
    // ═══════════════════════════════════════════════════════════
    
    try {
        var EditText = Java.use("android.widget.EditText");
        
        // Hook getText() — captures whenever any code reads input field content
        EditText.getText.implementation = function() {
            var result = this.getText();
            var text = result ? result.toString() : "";
            
            if (text.length > 0 && text.length <= 20) {
                // Get the hint to understand what field this is
                var hint = "";
                try { hint = this.getHint() ? this.getHint().toString() : ""; } catch(e) {}
                
                // Get input type to detect password/PIN fields
                var inputType = this.getInputType();
                var isPassword = (inputType & 0x80) !== 0 || (inputType & 0x10) !== 0;  // TYPE_TEXT_VARIATION_PASSWORD or TYPE_NUMBER_VARIATION_PASSWORD
                var isNumberPassword = (inputType & 0x12) !== 0; // TYPE_CLASS_NUMBER | TYPE_NUMBER_VARIATION_PASSWORD
                
                // Get the activity context
                var context = "";
                try {
                    var activity = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
                    context = activity.getPackageName();
                } catch(e) {}

                send({
                    type: "upi_input",
                    subtype: "edittext_read",
                    text_value: isPassword ? "[MASKED:" + text.length + "chars]" : text,
                    hint: hint,
                    input_type: inputType,
                    is_password_field: isPassword,
                    is_number_password: isNumberPassword,
                    field_length: text.length,
                    package: context,
                    timestamp: Date.now()
                });
            }
            return result;
        };
    } catch(e) { /* EditText hook failed */ }

    // ═══════════════════════════════════════════════════════════
    // 2. SharedPreferences — Detect credential storage
    // ═══════════════════════════════════════════════════════════
    
    try {
        var SharedPrefsEditor = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
        SharedPrefsEditor.putString.implementation = function(key, value) {
            var keyLower = key ? key.toLowerCase() : "";
            
            // Flag sensitive keys
            if (keyLower.indexOf("pin") >= 0 || keyLower.indexOf("upi") >= 0 ||
                keyLower.indexOf("otp") >= 0 || keyLower.indexOf("password") >= 0 ||
                keyLower.indexOf("token") >= 0 || keyLower.indexOf("secret") >= 0 ||
                keyLower.indexOf("credential") >= 0 || keyLower.indexOf("vpa") >= 0) {
                
                send({
                    type: "upi_input",
                    subtype: "sharedprefs_write",
                    key: key,
                    value_length: value ? value.length : 0,
                    is_sensitive: true,
                    timestamp: Date.now()
                });
            }
            return this.putString(key, value);
        };
    } catch(e) { /* SharedPreferences hook failed */ }

    // ═══════════════════════════════════════════════════════════
    // 3. Intent Monitoring — Captures UPI intents & broadcasts
    // ═══════════════════════════════════════════════════════════
    
    try {
        var Activity = Java.use("android.app.Activity");
        Activity.startActivity.overload("android.content.Intent").implementation = function(intent) {
            var action = intent.getAction() ? intent.getAction() : "null";
            var data = intent.getDataString() ? intent.getDataString() : "null";
            var component = intent.getComponent() ? intent.getComponent().flattenToString() : "null";
            var extras = "";
            
            try {
                var bundle = intent.getExtras();
                if (bundle) {
                    var keys = bundle.keySet();
                    var it = keys.iterator();
                    var extraList = [];
                    while (it.hasNext()) {
                        var key = it.next();
                        var val = bundle.get(key);
                        extraList.push(key + "=" + (val ? val.toString().substring(0, 200) : "null"));
                    }
                    extras = extraList.join("; ");
                }
            } catch(e) {}

            send({
                type: "intent",
                subtype: "start_activity",
                action: action,
                data: data,
                component: component,
                extras: extras,
                timestamp: Date.now()
            });

            this.startActivity(intent);
        };
    } catch(e) { /* Activity.startActivity hook failed */ }

    // Hook sendBroadcast
    try {
        var ContextWrapper = Java.use("android.content.ContextWrapper");
        ContextWrapper.sendBroadcast.overload("android.content.Intent").implementation = function(intent) {
            var action = intent.getAction() ? intent.getAction() : "null";
            var data = intent.getDataString() ? intent.getDataString() : "null";
            
            send({
                type: "intent",
                subtype: "broadcast",
                action: action,
                data: data,
                timestamp: Date.now()
            });

            this.sendBroadcast(intent);
        };
    } catch(e) { /* sendBroadcast hook failed */ }

    // ═══════════════════════════════════════════════════════════
    // 4. ContentResolver — Detect SMS/Contacts/CallLog reads
    // ═══════════════════════════════════════════════════════════
    
    try {
        var ContentResolver = Java.use("android.content.ContentResolver");
        ContentResolver.query.overload(
            "android.net.Uri",
            "[Ljava.lang.String;",
            "android.os.Bundle",
            "android.os.CancellationSignal"
        ).implementation = function(uri, projection, queryArgs, cancel) {
            var uriStr = uri.toString();
            
            // Flag access to sensitive content providers
            if (uriStr.indexOf("sms") >= 0 || uriStr.indexOf("contacts") >= 0 ||
                uriStr.indexOf("call_log") >= 0 || uriStr.indexOf("telephony") >= 0) {
                send({
                    type: "data_access",
                    subtype: "content_query",
                    uri: uriStr,
                    timestamp: Date.now()
                });
            }
            return this.query(uri, projection, queryArgs, cancel);
        };
    } catch(e) { /* ContentResolver hook failed */ }

    // ═══════════════════════════════════════════════════════════
    // 5. WebView JavaScript Interface — Data exfiltration via JS
    // ═══════════════════════════════════════════════════════════
    
    try {
        var WebView = Java.use("android.webkit.WebView");
        WebView.loadUrl.overload("java.lang.String").implementation = function(url) {
            send({
                type: "webview",
                subtype: "load_url",
                url: url,
                timestamp: Date.now()
            });
            this.loadUrl(url);
        };

        WebView.addJavascriptInterface.implementation = function(obj, name) {
            send({
                type: "webview",
                subtype: "js_interface",
                interface_name: name,
                object_class: obj.getClass().getName(),
                timestamp: Date.now()
            });
            this.addJavascriptInterface(obj, name);
        };
    } catch(e) { /* WebView hooks failed */ }

    send({type: "status", detail: "UPI & Payment hooks loaded successfully"});
});
