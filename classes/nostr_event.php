<?php
namespace auth_nostr;

defined('MOODLE_INTERNAL') || die();

/**
 * Nostr event verification helpers.
 */
class nostr_event {

    /**
     * Verify a Nostr event: ID integrity + Schnorr signature.
     *
     * @param array $event  Decoded JSON event object.
     */
    public static function verify(array $event): bool {
        $required = ['id', 'pubkey', 'created_at', 'kind', 'tags', 'content', 'sig'];
        foreach ($required as $field) {
            if (!array_key_exists($field, $event)) {
                return false;
            }
        }

        // Verify event ID matches its serialized content.
        if (self::compute_id($event) !== $event['id']) {
            return false;
        }

        return schnorr::verify($event['pubkey'], $event['id'], $event['sig']);
    }

    /**
     * Compute the event ID as defined by NIP-01:
     * SHA256(JSON([0, pubkey, created_at, kind, tags, content]))
     */
    public static function compute_id(array $event): string {
        $serialized = json_encode(
            [
                0,
                $event['pubkey'],
                (int) $event['created_at'],
                (int) $event['kind'],
                $event['tags'],
                $event['content'],
            ],
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        );

        return hash('sha256', $serialized);
    }

    /**
     * Extract the first value of a named tag from an event.
     *
     * @param array  $event
     * @param string $name   Tag name (first element of each tag array).
     * @return string|null   Second element (the value), or null if not found.
     */
    public static function get_tag(array $event, string $name): ?string {
        foreach ($event['tags'] as $tag) {
            if (isset($tag[0], $tag[1]) && $tag[0] === $name) {
                return (string) $tag[1];
            }
        }
        return null;
    }

    /**
     * Convert a hex-encoded 32-byte public key to its npub (bech32) representation (NIP-19).
     */
    public static function pubkey_to_npub(string $hex): string {
        $bytes = array_values(unpack('C*', hex2bin($hex)));
        $data  = self::bech32_convert_bits($bytes, 8, 5, true);
        return self::bech32_encode('npub', $data);
    }

    private static function bech32_polymod(array $values): int {
        $generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
        $chk = 1;
        foreach ($values as $v) {
            $top = $chk >> 25;
            $chk = ($chk & 0x1ffffff) << 5 ^ $v;
            for ($i = 0; $i < 5; $i++) {
                $chk ^= ($top >> $i & 1) ? $generator[$i] : 0;
            }
        }
        return $chk;
    }

    private static function bech32_hrp_expand(string $hrp): array {
        $ret = [];
        for ($i = 0, $len = strlen($hrp); $i < $len; $i++) {
            $ret[] = ord($hrp[$i]) >> 5;
        }
        $ret[] = 0;
        for ($i = 0, $len = strlen($hrp); $i < $len; $i++) {
            $ret[] = ord($hrp[$i]) & 31;
        }
        return $ret;
    }

    private static function bech32_encode(string $hrp, array $data): string {
        $charset  = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
        $combined = array_merge($data, [0, 0, 0, 0, 0, 0]);
        $polymod  = self::bech32_polymod(array_merge(self::bech32_hrp_expand($hrp), $combined)) ^ 1;
        $checksum = [];
        for ($i = 0; $i < 6; $i++) {
            $checksum[] = ($polymod >> (5 * (5 - $i))) & 31;
        }
        $result = $hrp . '1';
        foreach (array_merge($data, $checksum) as $c) {
            $result .= $charset[$c];
        }
        return $result;
    }

    private static function bech32_convert_bits(array $data, int $frombits, int $tobits, bool $pad = true): array {
        $acc  = 0;
        $bits = 0;
        $ret  = [];
        $maxv = (1 << $tobits) - 1;
        foreach ($data as $value) {
            $acc   = ($acc << $frombits) | $value;
            $bits += $frombits;
            while ($bits >= $tobits) {
                $bits -= $tobits;
                $ret[] = ($acc >> $bits) & $maxv;
            }
        }
        if ($pad && $bits > 0) {
            $ret[] = ($acc << ($tobits - $bits)) & $maxv;
        }
        return $ret;
    }
}
