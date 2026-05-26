<?php
namespace auth_nostr;

defined('MOODLE_INTERNAL') || die();

/**
 * BIP340 Schnorr signature verification over secp256k1.
 * Pure PHP implementation using the GMP extension.
 */
class schnorr {

    private const P_HEX  = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F';
    private const N_HEX  = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141';
    private const GX_HEX = '79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798';
    private const GY_HEX = '483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8';

    /** @var \GMP */
    private static $p = null;
    /** @var \GMP */
    private static $n = null;
    /** @var array{x:\GMP,y:\GMP} */
    private static $G = null;

    private static function init(): void {
        if (self::$p !== null) {
            return;
        }
        self::$p = gmp_init(self::P_HEX, 16);
        self::$n = gmp_init(self::N_HEX, 16);
        self::$G = [
            'x' => gmp_init(self::GX_HEX, 16),
            'y' => gmp_init(self::GY_HEX, 16),
        ];
    }

    /** Modular reduction — always returns a value in [0, m-1]. */
    private static function fe(\GMP $a): \GMP {
        $r = gmp_mod($a, self::$p);
        if (gmp_cmp($r, gmp_init(0)) < 0) {
            $r = gmp_add($r, self::$p);
        }
        return $r;
    }

    /**
     * Point addition on secp256k1.
     * Returns null to represent the point at infinity.
     *
     * @param array{x:\GMP,y:\GMP}|null $P
     * @param array{x:\GMP,y:\GMP}|null $Q
     * @return array{x:\GMP,y:\GMP}|null
     */
    private static function point_add(?array $P, ?array $Q): ?array {
        if ($P === null) {
            return $Q;
        }
        if ($Q === null) {
            return $P;
        }

        if (gmp_cmp($P['x'], $Q['x']) === 0) {
            // P == -Q → point at infinity.
            if (gmp_cmp($P['y'], $Q['y']) !== 0) {
                return null;
            }
            // P == Q → point doubling.
            $num = self::fe(gmp_mul(gmp_mul(gmp_init(3), $P['x']), $P['x']));
            $den = self::fe(gmp_mul(gmp_init(2), $P['y']));
            $lam = self::fe(gmp_mul($num, gmp_invert($den, self::$p)));
        } else {
            $num = self::fe(gmp_sub($Q['y'], $P['y']));
            $den = self::fe(gmp_sub($Q['x'], $P['x']));
            $lam = self::fe(gmp_mul($num, gmp_invert($den, self::$p)));
        }

        $x3 = self::fe(gmp_sub(gmp_sub(gmp_mul($lam, $lam), $P['x']), $Q['x']));
        $y3 = self::fe(gmp_sub(gmp_mul($lam, gmp_sub($P['x'], $x3)), $P['y']));

        return ['x' => $x3, 'y' => $y3];
    }

    /**
     * Scalar multiplication: scalar * P.
     * LSB-first double-and-add.
     *
     * @param \GMP $scalar
     * @param array{x:\GMP,y:\GMP} $P
     * @return array{x:\GMP,y:\GMP}|null
     */
    private static function point_mul(\GMP $scalar, array $P): ?array {
        $result = null;
        $addend = $P;
        $bits   = gmp_strval($scalar, 2);

        for ($i = strlen($bits) - 1; $i >= 0; $i--) {
            if ($bits[$i] === '1') {
                $result = self::point_add($result, $addend);
            }
            $addend = self::point_add($addend, $addend);
        }

        return $result;
    }

    /**
     * Given an x-coordinate, compute the corresponding point with even y.
     * Returns null if x is not on the curve.
     *
     * @return array{x:\GMP,y:\GMP}|null
     */
    private static function lift_x(\GMP $x): ?array {
        $p = self::$p;

        if (gmp_cmp($x, $p) >= 0) {
            return null;
        }

        // y² = x³ + 7 (mod p)
        $y_sq = self::fe(gmp_add(gmp_powm($x, gmp_init(3), $p), gmp_init(7)));

        // y = y_sq^((p+1)/4) mod p  — valid because p ≡ 3 (mod 4)
        $exp = gmp_div(gmp_add($p, gmp_init(1)), gmp_init(4));
        $y   = gmp_powm($y_sq, $exp, $p);

        // Verify the square root is correct.
        if (gmp_cmp(self::fe(gmp_mul($y, $y)), $y_sq) !== 0) {
            return null;
        }

        // Enforce even y.
        if (gmp_cmp(gmp_mod($y, gmp_init(2)), gmp_init(0)) !== 0) {
            $y = gmp_sub($p, $y);
        }

        return ['x' => $x, 'y' => $y];
    }

    /** BIP340 tagged hash: SHA256(SHA256(tag) ‖ SHA256(tag) ‖ msg). */
    private static function tagged_hash(string $tag, string $msg): string {
        $tag_hash = hash('sha256', $tag, true);
        return hash('sha256', $tag_hash . $tag_hash . $msg, true);
    }

    /**
     * Verify a BIP340 Schnorr signature.
     *
     * @param string $pubkey_hex  32-byte x-coordinate of public key (64 hex chars)
     * @param string $msg_hex     32-byte message / event id     (64 hex chars)
     * @param string $sig_hex     64-byte signature              (128 hex chars)
     */
    public static function verify(string $pubkey_hex, string $msg_hex, string $sig_hex): bool {
        if (!extension_loaded('gmp')) {
            throw new \RuntimeException('The GMP PHP extension is required for auth_nostr.');
        }

        self::init();

        if (strlen($pubkey_hex) !== 64 || strlen($msg_hex) !== 64 || strlen($sig_hex) !== 128) {
            return false;
        }

        $pubkey_bytes = hex2bin($pubkey_hex);
        $msg_bytes    = hex2bin($msg_hex);
        $sig_bytes    = hex2bin($sig_hex);

        if ($pubkey_bytes === false || $msg_bytes === false || $sig_bytes === false) {
            return false;
        }

        $P = self::lift_x(gmp_init($pubkey_hex, 16));
        if ($P === null) {
            return false;
        }

        $r = gmp_init(bin2hex(substr($sig_bytes, 0, 32)), 16);
        $s = gmp_init(bin2hex(substr($sig_bytes, 32, 32)), 16);

        if (gmp_cmp($r, self::$p) >= 0 || gmp_cmp($s, self::$n) >= 0) {
            return false;
        }

        // e = int(tagged_hash("BIP0340/challenge", bytes(r) ‖ pubkey ‖ msg)) mod n
        $e_input = substr($sig_bytes, 0, 32) . $pubkey_bytes . $msg_bytes;
        $e_hash  = self::tagged_hash('BIP0340/challenge', $e_input);
        $e       = gmp_mod(gmp_init(bin2hex($e_hash), 16), self::$n);

        // R = s·G + (n − e)·P
        $neg_e = gmp_sub(self::$n, $e);
        $R     = self::point_add(
            self::point_mul($s, self::$G),
            self::point_mul($neg_e, $P)
        );

        if ($R === null) {
            return false;
        }

        // R must have even y and R.x must equal r.
        if (gmp_cmp(gmp_mod($R['y'], gmp_init(2)), gmp_init(0)) !== 0) {
            return false;
        }

        return gmp_cmp($R['x'], $r) === 0;
    }
}
