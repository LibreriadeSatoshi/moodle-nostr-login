// AMD module — auth_nostr/nostr_login
// Adds a "Log in with Nostr" button to the Moodle login page.
// Implements NIP-07 (browser extension) + NIP-98 challenge-response.
define([], function() {
    'use strict';

    // Poll for window.nostr for up to `timeout` ms (NIP-07 may load async).
    var waitForExtension = function(timeout) {
        return new Promise(function(resolve) {
            var start = Date.now();
            var poll = function() {
                if (window.nostr) {
                    resolve(window.nostr);
                } else if (Date.now() - start < timeout) {
                    setTimeout(poll, 100);
                } else {
                    resolve(null);
                }
            };
            poll();
        });
    };

    // Fetch kind-0 (profile metadata) from a relay via WebSocket.
    // Resolves with the parsed content object, or null on timeout/error.
    var fetchKind0 = function(relay, pubkey, timeout) {
        return new Promise(function(resolve) {
            var timer = setTimeout(function() { resolve(null); }, timeout);
            try {
                var ws = new WebSocket(relay);
                ws.onopen = function() {
                    ws.send(JSON.stringify([
                        'REQ', 'auth-meta',
                        {kinds: [0], authors: [pubkey], limit: 1}
                    ]));
                };
                ws.onmessage = function(e) {
                    try {
                        var msg = JSON.parse(e.data);
                        if (msg[0] === 'EVENT' && msg[2] && msg[2].kind === 0) {
                            clearTimeout(timer);
                            ws.close();
                            resolve(JSON.parse(msg[2].content));
                        } else if (msg[0] === 'EOSE') {
                            clearTimeout(timer);
                            ws.close();
                            resolve(null);
                        }
                    } catch (_) {
                        clearTimeout(timer);
                        resolve(null);
                    }
                };
                ws.onerror = function() { clearTimeout(timer); resolve(null); };
            } catch (_) {
                clearTimeout(timer);
                resolve(null);
            }
        });
    };

    var setStatus = function(el, msg, isError) {
        el.textContent = msg;
        el.className = 'auth-nostr-status' + (isError ? ' auth-nostr-error' : '');
    };

    var handleLogin = async function(loginUrl, relay, btn, statusEl) {
        btn.disabled = true;

        setStatus(statusEl, 'Looking for Nostr extension…');
        var nostr = await waitForExtension(3000);
        if (!nostr) {
            setStatus(statusEl, 'No Nostr extension found. Install Alby or nos2x.', true);
            btn.disabled = false;
            return;
        }

        setStatus(statusEl, 'Requesting public key…');
        var pubkey;
        try {
            pubkey = await nostr.getPublicKey();
        } catch (_) {
            setStatus(statusEl, 'Extension denied access.', true);
            btn.disabled = false;
            return;
        }

        setStatus(statusEl, 'Fetching your Nostr profile…');
        var metadata = await fetchKind0(relay, pubkey, 3000);

        setStatus(statusEl, 'Requesting login challenge…');
        var nonce, signUrl;
        try {
            var challengeResp = await fetch(loginUrl + '?action=challenge');
            if (!challengeResp.ok) { throw new Error(); }
            var challengeData = await challengeResp.json();
            nonce   = challengeData.nonce;
            signUrl = challengeData.url;
        } catch (_) {
            setStatus(statusEl, 'Failed to get challenge. Reload and try again.', true);
            btn.disabled = false;
            return;
        }

        setStatus(statusEl, 'Signing login request…');
        var signedEvent;
        try {
            signedEvent = await nostr.signEvent({
                kind:       27235,
                created_at: Math.floor(Date.now() / 1000),
                content:    '',
                tags: [
                    ['u',         signUrl],
                    ['method',    'POST'],
                    ['challenge', nonce]
                ]
            });
        } catch (_) {
            setStatus(statusEl, 'Signing was cancelled.', true);
            btn.disabled = false;
            return;
        }

        setStatus(statusEl, 'Verifying with server…');
        var redirectUrl;
        try {
            var verifyResp = await fetch(loginUrl, {
                method:  'POST',
                headers: {'Content-Type': 'application/json'},
                body:    JSON.stringify({event: signedEvent, metadata: metadata})
            });
            var rawText = await verifyResp.text();
            var verifyData;
            try {
                verifyData = JSON.parse(rawText);
            } catch (_) {
                setStatus(statusEl, 'Server error (status ' + verifyResp.status + '): ' + rawText.substring(0, 200), true);
                btn.disabled = false;
                return;
            }
            if (!verifyResp.ok || verifyData.error) {
                setStatus(statusEl, verifyData.error || verifyData.message || 'Login failed. Please try again.', true);
                btn.disabled = false;
                return;
            }
            if (!verifyData.redirect) {
                setStatus(statusEl, 'Server error: missing redirect. Raw: ' + JSON.stringify(verifyData).substring(0, 200), true);
                btn.disabled = false;
                return;
            }
            redirectUrl = verifyData.redirect;
        } catch (err) {
            setStatus(statusEl, 'Network error: ' + (err && err.message ? err.message : String(err)), true);
            btn.disabled = false;
            return;
        }

        setStatus(statusEl, 'Logged in! Redirecting…');
        window.location.href = redirectUrl;
    };

    return {
        init: function(loginUrl, relay) {
            var ready = function(fn) {
                if (document.readyState !== 'loading') {
                    fn();
                } else {
                    document.addEventListener('DOMContentLoaded', fn);
                }
            };

            ready(function() {
                // Find the standard Moodle login form.
                var loginBtn = document.getElementById('loginbtn');
                if (!loginBtn) { return; }
                var form = loginBtn.closest('form');
                if (!form) { return; }

                // Build and inject the Nostr login widget after the form.
                var wrapper = document.createElement('div');
                wrapper.className = 'auth-nostr-wrapper mt-3 text-center';
                wrapper.innerHTML =
                    '<div class="auth-nostr-sep mb-2">' +
                        '<span class="auth-nostr-sep-text px-2">or</span>' +
                    '</div>' +
                    '<button type="button" id="auth-nostr-btn" class="btn btn-secondary w-100">' +
                        '⚡ Log in with Nostr' +
                    '</button>' +
                    '<div id="auth-nostr-status" class="auth-nostr-status mt-2 small"></div>';

                form.parentNode.insertBefore(wrapper, form.nextSibling);

                var btn      = document.getElementById('auth-nostr-btn');
                var statusEl = document.getElementById('auth-nostr-status');

                btn.addEventListener('click', function() {
                    handleLogin(loginUrl, relay, btn, statusEl);
                });
            });
        }
    };
});
