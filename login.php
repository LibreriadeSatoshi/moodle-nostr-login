<?php
/**
 * Nostr authentication endpoint.
 *
 * GET  ?action=challenge  →  Issue a one-time nonce for the client to sign.
 * POST (default)          →  Verify the signed NIP-98 event and log the user in.
 */

define('AJAX_SCRIPT', true);
define('NO_MOODLE_COOKIES', false);

require_once('../../config.php');
require_once($CFG->dirroot . '/login/lib.php');
require_once($CFG->dirroot . '/user/lib.php');

use auth_nostr\nostr_event;
use auth_nostr\schnorr;

$PAGE->set_url(new moodle_url('/auth/nostr/login.php'));
$PAGE->set_context(context_system::instance());

// All responses from this endpoint are JSON.
header('Content-Type: application/json; charset=utf-8');

$action = optional_param('action', '', PARAM_ALPHA);

// ── GET /auth/nostr/login.php?action=challenge ────────────────────────────────
if ($action === 'challenge') {
    if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
        http_response_code(405);
        echo json_encode(['error' => 'Method not allowed']);
        exit;
    }

    $nonce = bin2hex(random_bytes(32));
    $SESSION->auth_nostr_nonce      = $nonce;
    $SESSION->auth_nostr_nonce_time = time();

    echo json_encode([
        'nonce' => $nonce,
        'url'   => (new moodle_url('/auth/nostr/login.php'))->out(false),
    ]);
    exit;
}

// ── POST /auth/nostr/login.php ────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

$body = json_decode(file_get_contents('php://input'), true);

if (!is_array($body) || empty($body['event']) || !is_array($body['event'])) {
    http_response_code(400);
    echo json_encode(['error' => 'Missing or malformed event in request body']);
    exit;
}

$event    = $body['event'];
$metadata = $body['metadata'] ?? null;

// ── Validate session nonce (CSRF / replay protection) ─────────────────────────
if (empty($SESSION->auth_nostr_nonce) || empty($SESSION->auth_nostr_nonce_time)) {
    http_response_code(400);
    echo json_encode(['error' => 'No challenge found — reload the page and try again']);
    exit;
}

if ((time() - (int) $SESSION->auth_nostr_nonce_time) > 120) {
    unset($SESSION->auth_nostr_nonce, $SESSION->auth_nostr_nonce_time);
    http_response_code(400);
    echo json_encode(['error' => 'Challenge expired — reload the page and try again']);
    exit;
}

// ── Validate event fields ─────────────────────────────────────────────────────
if (!isset($event['kind']) || (int) $event['kind'] !== 27235) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid event kind (expected 27235)']);
    exit;
}

if (!isset($event['created_at']) || abs(time() - (int) $event['created_at']) > 60) {
    http_response_code(400);
    echo json_encode(['error' => 'Event timestamp is out of the 60-second window']);
    exit;
}

$challenge_tag = nostr_event::get_tag($event, 'challenge');
if ($challenge_tag !== $SESSION->auth_nostr_nonce) {
    http_response_code(400);
    echo json_encode(['error' => 'Challenge mismatch']);
    exit;
}

$url_tag   = nostr_event::get_tag($event, 'u');
$login_url = (new moodle_url('/auth/nostr/login.php'))->out(false);
if (!$url_tag || parse_url($url_tag, PHP_URL_PATH) !== parse_url($login_url, PHP_URL_PATH)) {
    http_response_code(400);
    echo json_encode(['error' => 'URL tag does not match']);
    exit;
}

$method_tag = nostr_event::get_tag($event, 'method');
if ($method_tag !== 'POST') {
    http_response_code(400);
    echo json_encode(['error' => 'Method tag must be POST']);
    exit;
}

// ── Verify cryptographic signature ───────────────────────────────────────────
try {
    $sig_valid = nostr_event::verify($event);
} catch (\RuntimeException $e) {
    http_response_code(500);
    echo json_encode(['error' => $e->getMessage()]);
    exit;
}

if (!$sig_valid) {
    http_response_code(401);
    echo json_encode(['error' => 'Invalid signature']);
    exit;
}

// Signature verified — consume the nonce so it cannot be reused.
unset($SESSION->auth_nostr_nonce, $SESSION->auth_nostr_nonce_time);

// ── Find or create the Moodle user ────────────────────────────────────────────
$pubkey_hex = $event['pubkey'];
$username   = 'nostr_' . substr($pubkey_hex, 0, 16);

$user = $DB->get_record('user', [
    'username'   => $username,
    'mnethostid' => $CFG->mnet_localhost_id,
    'deleted'    => 0,
]);

if (!$user) {
    if (!get_config('auth_nostr', 'autocreate')) {
        http_response_code(403);
        echo json_encode(['error' => 'Account auto-creation is disabled on this site']);
        exit;
    }

    // Derive display name from Nostr kind-0 metadata if the client provided it.
    $firstname = '';
    if (is_array($metadata)) {
        $firstname = trim($metadata['display_name'] ?? $metadata['name'] ?? '');
    }
    if ($firstname === '') {
        // Fallback: human-readable npub abbreviation.
        $firstname = substr($pubkey_hex, 0, 8) . '…' . substr($pubkey_hex, -4);
    }

    $newuser               = new stdClass();
    $newuser->auth         = 'nostr';
    $newuser->username     = $username;
    $newuser->firstname    = $firstname;
    $newuser->lastname     = 'Nostr';
    $newuser->email        = $username . '@' . parse_url($CFG->wwwroot, PHP_URL_HOST);
    $newuser->emailstop    = 1;
    $newuser->confirmed    = 1;
    $newuser->mnethostid   = $CFG->mnet_localhost_id;
    $newuser->lang         = $CFG->lang;
    $newuser->timecreated  = time();
    $newuser->timemodified = time();

    // Store the full hex pubkey as idnumber for future lookups / account linking.
    $newuser->idnumber = $pubkey_hex;

    try {
        $newuser->id = user_create_user($newuser, false, false);
    } catch (\Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => 'Could not create user account: ' . $e->getMessage()]);
        exit;
    }

    // Save hex pubkey to the custom profile field for visibility and future linking.
    require_once($CFG->dirroot . '/user/profile/lib.php');
    profile_save_data((object)[
        'id'                          => $newuser->id,
        'profile_field_nostrpubkey'   => nostr_event::pubkey_to_npub($pubkey_hex),
    ]);

    $user = get_complete_user_data('id', $newuser->id);
}

if (!$user) {
    http_response_code(500);
    echo json_encode(['error' => 'User record could not be loaded']);
    exit;
}

// ── Complete the Moodle login ─────────────────────────────────────────────────
complete_user_login($user);

$redirect = core_login_get_return_url();

echo json_encode(['redirect' => (string) $redirect]);
