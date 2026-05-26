<?php
defined('MOODLE_INTERNAL') || die();

if ($ADMIN->fulltree) {
    $settings->add(new admin_setting_configtext(
        'auth_nostr/relay',
        get_string('relay', 'auth_nostr'),
        get_string('relay_desc', 'auth_nostr'),
        'wss://relay.damus.io',
        PARAM_RAW_TRIMMED
    ));

    $settings->add(new admin_setting_configcheckbox(
        'auth_nostr/autocreate',
        get_string('autocreate', 'auth_nostr'),
        get_string('autocreate_desc', 'auth_nostr'),
        1
    ));
}
