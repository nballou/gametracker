'use strict';

// Object to accumulate data per SSL connection (keyed by its pointer as a string)
var accumulators = {};

// create global variables to track the latest presence and profile objects
if (!globalThis.latestPresenceObj) {
    globalThis.latestPresenceObj = null;
}
if (!globalThis.latestProfileObj) {
    globalThis.latestProfileObj = null;
}
if (!globalThis.processedPresenceCache) {
    globalThis.processedPresenceCache = {};
}

if (!globalThis.processedProfileCache) {
    globalThis.processedProfileCache = {};
}

// A helper function that decodes a Uint8Array as UTF‑8 using TextDecoder
function decodeUtf8(u8arr) {
    try {
        var decoder = new TextDecoder('utf-8', { fatal: false });
        return decoder.decode(u8arr);
    } catch (e) {
        var str = "";
        for (var i = 0; i < u8arr.length; i++) {
            if (u8arr[i] === 0) continue;
            str += String.fromCharCode(u8arr[i]);
        }
        return str;
    }
}

function dropAvatarsFromJsonString(jsonStr) {
    // This regex looks for the property "avatars": followed by an array (using non-greedy matching)
    // and an optional trailing comma.
    // It uses the /s flag (dotAll) so that the dot matches newline characters.
    return jsonStr.replace(/"avatars"\s*:\s*\[[\s\S]*?\](,)?/g, "");
}

function sanitizeAndDropAvatars(jsonStr) {
    // First, drop the avatars field entirely.
    let noAvatars = dropAvatarsFromJsonString(jsonStr);
    console.log("[*] JSON string after dropping avatars:", noAvatars);
    // Next, normalize the string to decompose diacritics and remove combining marks.
    let normalized = noAvatars.normalize("NFD").replace(/[\u0300-\u036f]/g, "");
    
    // Optionally, remove any remaining non-ASCII characters from keys if needed.
    normalized = normalized.replace(/"([^"]+)":/g, function(match, key) {
        let cleanedKey = key.replace(/[^\x00-\x7F]/g, "");
        return `"${cleanedKey}":`;
    });
    
    return normalized;
}

// Custom function to extract a JSON object from a UTF‑8 decoded string given a start pattern
function extractJSON(utf8Str, startPattern) {
    var startIdx = utf8Str.indexOf(startPattern);
    if (startIdx === -1) {
        return null;
    }
    var braceCount = 0;
    var endIdx = -1;
    for (var i = startIdx; i < utf8Str.length; i++) {
        var ch = utf8Str[i];
        if (ch === '{') {
            braceCount++;
        } else if (ch === '}') {
            braceCount--;
            if (braceCount === 0) {
                endIdx = i;
                break;
            }
        }
    }
    if (endIdx !== -1) {
        return utf8Str.substring(startIdx, endIdx + 1);
    }
    return null;
}

Interceptor.attach(Module.findExportByName("libssl.so", "SSL_read"), {
    onEnter: function(args) {
        this.sslPtr = args[0].toString();
        this.buf = args[1];
        this.num = args[2].toInt32();
    },
    onLeave: function(retval) {
        var bytesRead = retval.toInt32();
        if (bytesRead <= 0) return;
        try {
            // Read the current chunk into a Uint8Array
            var chunk = new Uint8Array(bytesRead);
            for (var i = 0; i < bytesRead; i++) {
                chunk[i] = Memory.readU8(this.buf.add(i));
            }

            // Update accumulator for this SSL connection
            if (!accumulators[this.sslPtr]) {
                accumulators[this.sslPtr] = new Uint8Array(0);
            }
            var oldData = accumulators[this.sslPtr];
            var combined = new Uint8Array(oldData.length + chunk.length);
            combined.set(oldData, 0);
            combined.set(chunk, oldData.length);
            accumulators[this.sslPtr] = combined;

            // Decode accumulated bytes
            var utf8Str = decodeUtf8(combined);

            // Only proceed if one of the keywords is present
            if (utf8Str.indexOf("basicPresences") === -1 &&
                utf8Str.indexOf("profiles") === -1) {
                return;
            }

            // Process "basicPresences"
            if (utf8Str.indexOf("basicPresences") !== -1) {
                var presenceJsonStr = extractJSON(utf8Str, '{"basicPresences":');
                if (presenceJsonStr) {
                    // Use cache to avoid duplicate processing
                    if (globalThis.processedPresenceCache[presenceJsonStr]) {
                        // Already processed; skip.
                    } else {
                        globalThis.processedPresenceCache[presenceJsonStr] = true;
                        console.log("[*] Extracted JSON for presence:");
                        console.log(presenceJsonStr);
                        var cleanPresenceStr = sanitizeAndDropAvatars(presenceJsonStr);
                        try {
                            var presenceObj = JSON.parse(cleanPresenceStr);
                            globalThis.latestPresenceObj = presenceObj; // Persist the latest presence data globally.
                        } catch (e) {
                            console.error("[!] JSON parse error (presence): " + e);
                        }
                    }
                } else {
                    console.error("[!] Could not extract valid JSON boundaries for presence.");
                }
            }

            // Process "profiles"
            if (utf8Str.indexOf("profiles") !== -1) {
                console.log("[*] Found profiles in the string.");
                var profileJsonStr = extractJSON(utf8Str, '{"profiles":');
                if (profileJsonStr) {
                    console.log("[DEBUG] Checking profiles cache for JSON:", profileJsonStr);
                    if (globalThis.processedProfileCache[profileJsonStr]) {
                        console.log("[DEBUG] This profile JSON was already processed, returning early.");
                    } else {
                        globalThis.processedProfileCache[profileJsonStr] = true;
                        console.log("[*] Extracted JSON for profiles:");
                        console.log(profileJsonStr);
                        try {
                            var profileObj = JSON.parse(profileJsonStr);
                            // Persist the latest profile data globally.
                            globalThis.latestProfileObj = profileObj;
                        } catch (e) {
                            console.error("[!] JSON parse error (profiles): " + e);
                        }
                    }
                } else {
                    console.error("[!] Could not extract valid JSON boundaries for profiles.");
                }
            }

            // Check if both the latest presence and profile objects are available.
            if (globalThis.latestPresenceObj && globalThis.latestProfileObj) {
                console.log("[*] Both JSON objects are available (from globals), merging and generating CSV.");
                var presences = globalThis.latestPresenceObj.basicPresences;
                var profiles = globalThis.latestProfileObj.profiles;

                if (presences && profiles) {
                    var csvStr = "platform,userName,accountID,presenceState,presenceText,presencePlatform,titleId,gamerScore,multiplayerSummary,lastSeen\n";
                    for (var i = 0; i < presences.length; i++) {
                        var presence = presences[i];
                        var profile = profiles[i] || {};
                        var platformInfo = presence.primaryPlatformInfo || {};

                        // Adjust as needed: ensure gameTitleInfoList exists if you access it.
                        var platform = "PlayStation";
                        var userName = profile.onlineId || "";
                        var accountID = presence.accountId || "";
                        var presenceState = platformInfo.onlineStatus || "";
                        // Accessing nested objects should be guarded.
                        var presenceText = (presence.gameTitleInfoList && presence.gameTitleInfoList.titleName) || "";
                        var presencePlatform = (presence.gameTitleInfoList && presence.gameTitleInfoList.launchPlatform) || "";
                        var titleId = (presence.gameTitleInfoList && presence.gameTitleInfoList.npTitleId) || "";
                        var gamerScore = "";
                        var multiplayerSummary = "";
                        var lastSeen = platformInfo.lastOnlineDate || "";
                        
                        csvStr += platform + "," +
                                  userName + "," +
                                  accountID + "," +
                                  presenceState + "," +
                                  presenceText + "," +
                                  presencePlatform + "," +
                                  titleId + "," +
                                  gamerScore + "," +
                                  multiplayerSummary + "," +
                                  lastSeen + "\n";
                    }
                    console.log("[*] Generated CSV data:");
                    console.log(csvStr);
                    send({type: "csv-data", csv: csvStr, platform: "PlayStation"});
                } else {
                    console.error("[!] Missing presences or profiles arrays.");
                }
                
                // Clear persisted globals and caches to start fresh for the next cycle.
                globalThis.latestPresenceObj = null;
                globalThis.latestProfileObj = null;
                globalThis.processedPresenceCache = {};
                globalThis.processedProfileCache = {};
            }
            
            // Clear the accumulator for the current SSL connection after processing.
            delete accumulators[this.sslPtr];
        } catch (e) {
            // Optionally, log errors here.
            // console.error("[!] Error processing SSL data: " + e);
        }
    }
});
