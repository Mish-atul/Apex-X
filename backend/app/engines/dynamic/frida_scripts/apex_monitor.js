// APEX-X sensitive-API monitor.
// Observational only: records which privacy/security-relevant APIs the app
// invokes at runtime and reports them to the host for the analysis report.
// Every hook calls the original method unchanged.
'use strict';

var reported = {};
function emit(category, api, risk, detail) {
    var key = api + '|' + String(detail).substring(0, 100);
    if (reported[key]) return;
    reported[key] = true;
    send({ type: 'apex_event', category: category, api: api, risk: risk,
           detail: String(detail).substring(0, 300) });
}

function safe(label, fn) {
    try { fn(); } catch (e) { /* class/overload absent on this app or API level */ }
}

Java.perform(function () {
    // ── Device identifiers (tracking / fingerprinting) ──
    safe('TelephonyManager', function () {
        var TM = Java.use('android.telephony.TelephonyManager');
        ['getDeviceId', 'getImei', 'getSubscriberId', 'getSimSerialNumber', 'getLine1Number'].forEach(function (m) {
            if (TM[m]) {
                TM[m].overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        emit('data_exfil', 'TelephonyManager.' + m + '()', 'HIGH', 'Reads hardware/SIM identifier');
                        return ov.apply(this, arguments);
                    };
                });
            }
        });
    });

    // ── SMS send (toll fraud / OTP theft) ──
    safe('SmsManager', function () {
        var SM = Java.use('android.telephony.SmsManager');
        SM.sendTextMessage.overload('java.lang.String', 'java.lang.String', 'java.lang.String',
            'android.app.PendingIntent', 'android.app.PendingIntent').implementation =
            function (dest, sc, text, a, b) {
                emit('sms', 'SmsManager.sendTextMessage()', 'CRITICAL', 'Sends SMS to ' + dest);
                return this.sendTextMessage(dest, sc, text, a, b);
            };
    });

    // ── Content provider reads (SMS inbox, contacts, call log) ──
    safe('ContentResolver', function () {
        var CR = Java.use('android.content.ContentResolver');
        CR.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String',
            '[Ljava.lang.String;', 'java.lang.String').implementation =
            function (uri, a, b, c, d) {
                var u = uri ? uri.toString() : '';
                if (/sms|mms|contacts|call_log|calllog/i.test(u)) {
                    emit('data_exfil', 'ContentResolver.query()', 'CRITICAL', 'Reads ' + u);
                }
                return this.query(uri, a, b, c, d);
            };
    });

    // ── Clipboard access (credential / 2FA scraping) ──
    safe('Clipboard', function () {
        var CM = Java.use('android.content.ClipboardManager');
        CM.getPrimaryClip.implementation = function () {
            emit('data_exfil', 'ClipboardManager.getPrimaryClip()', 'HIGH', 'Reads clipboard contents');
            return this.getPrimaryClip();
        };
    });

    // ── OS command execution ──
    safe('Runtime.exec', function () {
        var RT = Java.use('java.lang.Runtime');
        RT.exec.overload('java.lang.String').implementation = function (cmd) {
            emit('command_exec', 'Runtime.exec()', 'CRITICAL', 'Executes: ' + cmd);
            return this.exec(cmd);
        };
        RT.exec.overload('[Ljava.lang.String;').implementation = function (arr) {
            emit('command_exec', 'Runtime.exec()', 'CRITICAL', 'Executes: ' + arr.join(' '));
            return this.exec(arr);
        };
    });

    // ── Dynamic code loading (payload staging) ──
    ['dalvik.system.DexClassLoader', 'dalvik.system.PathClassLoader',
     'dalvik.system.InMemoryDexClassLoader'].forEach(function (cls) {
        safe(cls, function () {
            var CL = Java.use(cls);
            CL.$init.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    var arg = arguments.length ? String(arguments[0]) : '';
                    emit('dynamic_loading', cls.split('.').pop() + '()', 'CRITICAL', 'Loads code: ' + arg);
                    return ov.apply(this, arguments);
                };
            });
        });
    });

    // ── Accessibility service start (overlay / screen scraping) ──
    safe('AccessibilityService', function () {
        var AS = Java.use('android.accessibilityservice.AccessibilityService');
        AS.onServiceConnected.implementation = function () {
            emit('surveillance', 'AccessibilityService.onServiceConnected()', 'CRITICAL',
                 'Accessibility service became active');
            return this.onServiceConnected();
        };
    });

    // ── Location access ──
    safe('LocationManager', function () {
        var LM = Java.use('android.location.LocationManager');
        if (LM.getLastKnownLocation) {
            LM.getLastKnownLocation.overload('java.lang.String').implementation = function (p) {
                emit('surveillance', 'LocationManager.getLastKnownLocation()', 'HIGH', 'Reads device location');
                return this.getLastKnownLocation(p);
            };
        }
    });

    // ── Crypto (ransomware / data hiding indicator) ──
    safe('Cipher', function () {
        var C = Java.use('javax.crypto.Cipher');
        C.doFinal.overload('[B').implementation = function (b) {
            emit('crypto', 'Cipher.doFinal()', 'MEDIUM', 'Encrypts/decrypts a ' + (b ? b.length : 0) + '-byte buffer');
            return this.doFinal(b);
        };
    });

    send({ type: 'apex_event', category: 'system', api: 'Frida Monitor Attached',
           risk: 'LOW', detail: 'Runtime instrumentation active' });
});
