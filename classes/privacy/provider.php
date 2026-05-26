<?php
namespace auth_nostr\privacy;

defined('MOODLE_INTERNAL') || die();

use core_privacy\local\metadata\null_provider;

/**
 * Privacy provider for auth_nostr.
 *
 * Personal data (public key, display name) is stored in core Moodle user
 * tables and handled by core privacy subsystems. This plugin itself holds
 * no additional personal data.
 */
class provider implements null_provider {

    public static function get_reason(): string {
        return 'privacy:metadata';
    }
}
