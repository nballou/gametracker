'use strict';

// Object to accumulate data per SSL connection (keyed by its pointer as a string)
var accumulators = {};

// Global vars to track latest JSON objects
if (!globalThis.latestPresenceObj)     globalThis.latestPresenceObj = null;
if (!globalThis.latestProfileObj)      globalThis.latestProfileObj = null;
if (!globalThis.processedPresenceCache) globalThis.processedPresenceCache = {};
if (!globalThis.processedProfileCache)  globalThis.processedProfileCache = {};

// Helper: decode a memory buffer as UTF-8, resilient to null bytes
function decodeUtf8(ptr, length) {
    try {
        return Memory.readUtf8String(ptr, length);
    } catch (e) {
        var txt = '';
        for (var i = 0; i < length; i++) {
            var byte = Memory.readU8(ptr.add(i));
            if (byte === 0) continue;
            txt += String.fromCharCode(byte);
        }
        return txt;
    }
}

// Helper: strip invalid control characters from a JSON snippet
function sanitizeJson(str) {
    // Remove U+0000–U+001F and U+007F–U+009F
    return str.replace(/[\u0000-\u001F\u007F-\u009F]+/g, '');
}

// Extract a balanced JSON object starting at a given pattern
function extractJSON(utf8Str, startPattern) {
    var startIdx = utf8Str.indexOf(startPattern);
    if (startIdx === -1) return null;
    var braceCount = 0;
    for (var i = startIdx; i < utf8Str.length; i++) {
        var ch = utf8Str[i];
        if (ch === '{') braceCount++;
        else if (ch === '}') {
            braceCount--;
            if (braceCount === 0) {
                return utf8Str.substring(startIdx, i + 1);
            }
        }
    }
    return null;
}

Interceptor.attach(
    Module.findExportByName('libssl.so', 'SSL_read'),
    {
        onEnter: function (args) {
            this.sslPtr = args[0].toString();
            this.buf    = args[1];
            this.num    = args[2].toInt32();
        },
        onLeave: function (retval) {
            var bytesRead = retval.toInt32();
            if (bytesRead <= 0) return;

            try {
                // Decode and accumulate
                var text = decodeUtf8(this.buf, bytesRead);
                accumulators[this.sslPtr] = (accumulators[this.sslPtr] || '') + text;
                var accumulated = accumulators[this.sslPtr];
                console.log(`[PS] Accumulator length for ptr=${this.sslPtr}: ${accumulated.length}`);

                // Show raw snippets
                if (accumulated.includes('basicPresences')) {
                    var idx = accumulated.indexOf('basicPresences');
                    console.log(
                        '[PS][RAW PRESENCE] ...',
                        accumulated.slice(Math.max(0, idx - 50), idx + 200).replace(/\n/g, ' ')
                    );
                }
                if (accumulated.includes('profiles')) {
                    var idx2 = accumulated.indexOf('profiles');
                    console.log(
                        '[PS][RAW PROFILE] ...',
                        accumulated.slice(Math.max(0, idx2 - 50), idx2 + 200).replace(/\n/g, ' ')
                    );
                }

                // Presence JSON
                var presenceObj = null;
                if (accumulated.includes('basicPresences')) {
                    console.log('[PS] Found basicPresences, extracting JSON...');
                    var presStr = extractJSON(accumulated, '{"basicPresences":');
                    if (presStr) {
                        presStr = sanitizeJson(presStr);
                        try {
                            presenceObj = JSON.parse(presStr);
                            console.log('[PS][PARSED PRESENCE OBJ]', JSON.stringify(presenceObj, null, 2));
                            globalThis.latestPresenceObj = presenceObj;
                        } catch (e) {
                            console.error('[PS][ERROR] JSON.parse.presence failed:', e);
                        }
                    } else {
                        console.error('[PS][ERROR] Could not extract basicPresences JSON');
                    }
                }

                // Profile JSON
                var profileObj = null;
                if (accumulated.includes('profiles')) {
                    console.log('[PS] Found profiles, extracting JSON...');
                    var profStr = extractJSON(accumulated, '{"profiles":');
                    if (profStr) {
                        profStr = sanitizeJson(profStr);
                        try {
                            profileObj = JSON.parse(profStr);
                            console.log('[PS][PARSED PROFILE OBJ]', JSON.stringify(profileObj, null, 2));
                            globalThis.latestProfileObj = profileObj;
                        } catch (e) {
                            console.error('[PS][ERROR] JSON.parse.profiles failed:', e);
                        }
                    } else {
                        console.error('[PS][ERROR] Could not extract profiles JSON');
                    }
                }

                // Merge when ready
                if (globalThis.latestPresenceObj && globalThis.latestProfileObj) {
                    console.log('[*] Both JSON objects available; generating CSV...');
                    var presences = globalThis.latestPresenceObj.basicPresences;
                    var profiles  = globalThis.latestProfileObj.profiles;
                    if (presences && profiles) {
                        var csv = 'platform,userName,accountID,presenceState,presenceText,presencePlatform,titleId,gamerScore,multiplayerSummary,lastSeen\n';
                        presences.forEach(function(p, i) {
                            var prof = profiles[i] || {};
                            var info = p.primaryPlatformInfo || {};
                            csv += [
                                'PlayStation',
                                prof.onlineId || '',
                                p.accountId || '',
                                info.onlineStatus || '',
                                (p.gameTitleInfoList||{}).titleName || '',
                                (p.gameTitleInfoList||{}).launchPlatform || '',
                                (p.gameTitleInfoList||{}).npTitleId || '',
                                '',
                                '',
                                info.lastOnlineDate || ''
                            ].join(',') + '\n';
                        });
                        console.log('[*] Generated CSV snippet:', csv.slice(0,200).replace(/\n/g,' '));
                        send({ type: 'csv-data', csv: csv, platform: 'PlayStation' });
                    } else {
                        console.error('[!] Missing basicPresences or profiles arrays.');
                    }

                    // Reset for next cycle
                    globalThis.latestPresenceObj = null;
                    globalThis.latestProfileObj = null;
                    accumulators[this.sslPtr] = '';
                    globalThis.processedPresenceCache = {};
                    globalThis.processedProfileCache = {};
                }
            } catch (e) {
                console.error('[!] Error in onLeave:', e);
            }
        }
    }
);
