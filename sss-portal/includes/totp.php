<?php
/**
 * Zero-Dependency Enterprise TOTP & Pure-PHP SVG QR Code Engine
 * 
 * Implements:
 *  - RFC 6238 (TOTP: Time-Based One-Time Password Algorithm)
 *  - RFC 4226 (HOTP: An HMAC-Based One-Time Password Algorithm)
 *  - RFC 4648 (Base32 decoding & encoding)
 *  - ISO/IEC 18004 specification for pure-PHP SVG QR-Code matrix rendering
 * 
 * Works seamlessly with:
 *  - Google Authenticator
 *  - Microsoft Authenticator
 *  - Authy
 *  - 1Password / Bitwarden
 *  - Apple Passwords & iOS Camera
 * 
 * @package SuperShield_Portal
 * @author  Ghulam Rasool <grwebdevs.com>
 * @version 2.2.1
 */

defined('SSS_ACCESS') or define('SSS_ACCESS', true);

class SSS_TOTP {

    /**
     * Base32 character map for RFC 4648.
     */
    private static $b32_alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /**
     * Generate a cryptographically secure 16-character Base32 secret key.
     *
     * @param int $length
     * @return string
     */
    public static function generate_secret($length = 16) {
        $secret = '';
        $alphabet_length = strlen(self::$b32_alphabet);

        for ($i = 0; $i < $length; $i++) {
            $random_index = function_exists('random_int') ? random_int(0, $alphabet_length - 1) : mt_rand(0, $alphabet_length - 1);
            $secret .= self::$b32_alphabet[$random_index];
        }

        return $secret;
    }

    /**
     * Format a secret with spaces for effortless human readability (e.g. ABCD EFGH IJKL MNOP).
     *
     * @param string $secret
     * @return string
     */
    public static function format_secret($secret) {
        $clean = strtoupper(preg_replace('/[^A-Z2-7]/', '', (string)$secret));
        return trim(chunk_split($clean, 4, ' '));
    }

    /**
     * Decode RFC 4648 Base32 string into binary bytes.
     *
     * @param string $b32
     * @return string|false
     */
    public static function base32_decode($b32) {
        $b32 = strtoupper(trim($b32));
        $b32 = preg_replace('/[^A-Z2-7]/', '', $b32);

        if (empty($b32)) {
            return false;
        }

        $binary_string = '';
        $buffer = 0;
        $bits_left = 0;

        for ($i = 0, $len = strlen($b32); $i < $len; $i++) {
            $val = strpos(self::$b32_alphabet, $b32[$i]);
            if (false === $val) {
                continue;
            }

            $buffer = ($buffer << 5) | $val;
            $bits_left += 5;

            if ($bits_left >= 8) {
                $bits_left -= 8;
                $binary_string .= chr(($buffer >> $bits_left) & 0xFF);
            }
        }

        return $binary_string;
    }

    /**
     * Calculate 6-digit TOTP code for a secret and 30-second time slice.
     *
     * @param string   $secret Base32 secret.
     * @param int|null $time_slice 30-second interval (defaults to current time).
     * @return string|false
     */
    public static function get_totp_code($secret, $time_slice = null) {
        if (null === $time_slice) {
            $time_slice = (int) floor(time() / 30);
        }

        $key = self::base32_decode($secret);
        if (false === $key) {
            return false;
        }

        // Pack counter as 64-bit big-endian integer
        $packed_time = pack('N*', 0) . pack('N*', $time_slice);

        // HMAC-SHA1
        $hash = hash_hmac('sha1', $packed_time, $key, true);

        // Dynamic truncation (RFC 4226)
        $offset = ord(substr($hash, -1)) & 0x0F;
        $truncated_hash = substr($hash, $offset, 4);

        $value = unpack('N', $truncated_hash);
        $value = $value[1] & 0x7FFFFFFF;

        $modulo = 1000000;
        return str_pad((string)($value % $modulo), 6, '0', STR_PAD_LEFT);
    }

    /**
     * Verify a submitted TOTP code with standard clock-drift allowance (+/- 1 time step = 30s).
     *
     * @param string $secret
     * @param string $code
     * @param int    $discrepancy Windows to check before and after (1 = +/- 30s).
     * @return bool
     */
    public static function verify_totp($secret, $code, $discrepancy = 1) {
        $code = trim(str_replace(array(' ', '-'), '', (string)$code));
        if (strlen($code) !== 6 || !ctype_digit($code)) {
            return false;
        }

        $current_slice = (int) floor(time() / 30);

        for ($i = -$discrepancy; $i <= $discrepancy; $i++) {
            $calculated = self::get_totp_code($secret, $current_slice + $i);
            if (false !== $calculated && hash_equals((string)$calculated, $code)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Generate standard otpauth:// URI string for mobile authenticators.
     *
     * @param string $username
     * @param string $secret
     * @param string $issuer
     * @return string
     */
    public static function get_otpauth_url($username, $secret, $issuer = 'SuperShield') {
        $clean_issuer = trim(preg_replace('/[^a-zA-Z0-9 _-]/', '', (string)$issuer));
        if (empty($clean_issuer)) {
            $clean_issuer = 'SuperShield';
        }
        $clean_user = trim(preg_replace('/[^a-zA-Z0-9@._-]/', '', (string)$username));
        if (empty($clean_user)) {
            $clean_user = 'ghulam';
        }

        $label = rawurlencode($clean_issuer) . ':' . rawurlencode($clean_user);
        $issuer_param = rawurlencode($clean_issuer);

        return "otpauth://totp/{$label}?secret={$secret}&issuer={$issuer_param}&algorithm=SHA1&digits=6&period=30";
    }

    /**
     * Generate 8 single-use emergency backup recovery codes.
     *
     * @param int $count
     * @return array<string> Formatted codes (e.g. ['A4X9-K2P8', ...])
     */
    public static function generate_backup_codes($count = 8) {
        $codes = array();
        $chars = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
        $chars_len = strlen($chars);

        for ($i = 0; $i < $count; $i++) {
            $part1 = '';
            $part2 = '';
            for ($j = 0; $j < 4; $j++) {
                $part1 .= $chars[random_int(0, $chars_len - 1)];
                $part2 .= $chars[random_int(0, $chars_len - 1)];
            }
            $codes[] = $part1 . '-' . $part2;
        }

        return $codes;
    }

    /**
     * Render crisp vector SVG QR-Code matrix for the otpauth URI.
     *
     * @param string $data
     * @param int    $pixel_size
     * @return string
     */
    public static function render_qr_svg($data, $pixel_size = 220) {
        return SSS_QRCode::get_svg($data, $pixel_size);
    }
}

/**
 * Pure-PHP ISO/IEC 18004 Compliant QR Code Generator
 * Zero dependencies, no Imagick, no GD, no external web APIs.
 */
class SSS_QRCode {

    const EC_L = 1; // 7% recovery
    const EC_M = 0; // 15% recovery

    private static $capacities = array(
        1  => array( 1 => 17,  0 => 14 ),
        2  => array( 1 => 32,  0 => 26 ),
        3  => array( 1 => 53,  0 => 42 ),
        4  => array( 1 => 78,  0 => 62 ),
        5  => array( 1 => 106, 0 => 84 ),
        6  => array( 1 => 134, 0 => 106 ),
        7  => array( 1 => 154, 0 => 122 ),
        8  => array( 1 => 192, 0 => 152 ),
        9  => array( 1 => 230, 0 => 180 ),
        10 => array( 1 => 271, 0 => 213 ),
    );

    private static $total_codewords = array(
        1 => 26, 2 => 44, 3 => 70, 4 => 100, 5 => 134,
        6 => 172, 7 => 196, 8 => 242, 9 => 292, 10 => 346,
    );

    private static $block_specs = array(
        1  => array( 1 => array( array( 1, 19, 7 ) ),                0 => array( array( 1, 16, 10 ) ) ),
        2  => array( 1 => array( array( 1, 34, 10 ) ),               0 => array( array( 1, 28, 16 ) ) ),
        3  => array( 1 => array( array( 1, 55, 15 ) ),               0 => array( array( 1, 44, 26 ) ) ),
        4  => array( 1 => array( array( 1, 80, 20 ) ),               0 => array( array( 2, 36, 18 ) ) ),
        5  => array( 1 => array( array( 1, 108, 26 ) ),              0 => array( array( 2, 48, 24 ) ) ),
        6  => array( 1 => array( array( 2, 68, 18 ) ),               0 => array( array( 4, 32, 16 ) ) ),
        7  => array( 1 => array( array( 2, 78, 20 ) ),               0 => array( array( 4, 39, 18 ) ) ),
        8  => array( 1 => array( array( 2, 97, 24 ) ),               0 => array( array( 4, 46, 22 ), array( 2, 47, 22 ) ) ),
        9  => array( 1 => array( array( 2, 116, 30 ) ),              0 => array( array( 4, 53, 22 ), array( 4, 54, 22 ) ) ),
        10 => array( 1 => array( array( 2, 68, 18 ), array( 2, 69, 18 ) ), 0 => array( array( 6, 43, 26 ), array( 2, 44, 26 ) ) ),
    );

    private static $align_patterns = array(
        1  => array(),
        2  => array( 6, 18 ),
        3  => array( 6, 22 ),
        4  => array( 6, 26 ),
        5  => array( 6, 30 ),
        6  => array( 6, 34 ),
        7  => array( 6, 22, 38 ),
        8  => array( 6, 24, 42 ),
        9  => array( 6, 26, 46 ),
        10 => array( 6, 28, 50 ),
    );

    private static $gf_exp = null;
    private static $gf_log = null;

    private static function init_gf() {
        if (null !== self::$gf_exp) {
            return;
        }

        self::$gf_exp = array_fill(0, 512, 0);
        self::$gf_log = array_fill(0, 256, 0);

        $x = 1;
        for ($i = 0; $i < 255; $i++) {
            self::$gf_exp[$i] = $x;
            self::$gf_log[$x] = $i;
            $x <<= 1;
            if ($x & 0x100) {
                $x ^= 0x11D;
            }
        }

        for ($i = 255; $i < 512; $i++) {
            self::$gf_exp[$i] = self::$gf_exp[$i - 255];
        }
    }

    private static function gf_mul($x, $y) {
        if (0 === $x || 0 === $y) {
            return 0;
        }
        return self::$gf_exp[self::$gf_log[$x] + self::$gf_log[$y]];
    }

    private static function rs_generator_poly($n) {
        $g = array(1);
        for ($i = 0; $i < $n; $i++) {
            $next_term = array(1, self::$gf_exp[$i]);
            $res = array_fill(0, count($g) + 1, 0);
            for ($j = 0; $j < count($g); $j++) {
                $res[$j] ^= self::gf_mul($g[$j], $next_term[0]);
                $res[$j + 1] ^= self::gf_mul($g[$j], $next_term[1]);
            }
            $g = $res;
        }
        return $g;
    }

    private static function calculate_rs_block($data_bytes, $ec_count) {
        self::init_gf();
        $gen = self::rs_generator_poly($ec_count);
        $info = array_merge($data_bytes, array_fill(0, $ec_count, 0));

        for ($i = 0; $i < count($data_bytes); $i++) {
            $coef = $info[$i];
            if (0 !== $coef) {
                for ($j = 0; $j < count($gen); $j++) {
                    $info[$i + $j] ^= self::gf_mul($gen[$j], $coef);
                }
            }
        }

        return array_slice($info, count($data_bytes), $ec_count);
    }

    public static function get_svg($text, $pixel_size = 220, $ec_level = self::EC_L) {
        $matrix = self::encode($text, $ec_level);
        $size = count($matrix);
        $quiet_zone = 4;
        $grid_size = $size + ($quiet_zone * 2);
        $box = $pixel_size / $grid_size;

        $rects = '';
        for ($r = 0; $r < $size; $r++) {
            for ($c = 0; $c < $size; $c++) {
                if (1 === $matrix[$r][$c]) {
                    $x = round(($c + $quiet_zone) * $box, 2);
                    $y = round(($r + $quiet_zone) * $box, 2);
                    $w = round($box, 2);
                    $rects .= "<rect x='{$x}' y='{$y}' width='{$w}' height='{$w}' fill='#0a0f1d'/>\n";
                }
            }
        }

        return "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {$pixel_size} {$pixel_size}' width='{$pixel_size}' height='{$pixel_size}' shape-rendering='crispEdges'>\n" .
            "<rect width='100%' height='100%' fill='#ffffff' rx='10'/>\n" .
            $rects .
            "</svg>";
    }

    private static function mask_cond($mask_id, $r, $c) {
        switch ($mask_id) {
            case 0: return (($r + $c) % 2 === 0);
            case 1: return ($r % 2 === 0);
            case 2: return ($c % 3 === 0);
            case 3: return (($r + $c) % 3 === 0);
            case 4: return (((int)($r / 2) + (int)($c / 3)) % 2 === 0);
            case 5: return ((($r * $c) % 2 + ($r * $c) % 3) === 0);
            case 6: return (((($r * $c) % 2 + ($r * $c) % 3) % 2) === 0);
            case 7: return (((($r + $c) % 2 + ($r * $c) % 3) % 2) === 0);
        }
        return false;
    }

    private static function penalty_score(&$matrix, $size) {
        $penalty = 0;

        for ($r = 0; $r < $size; $r++) {
            $run = 1;
            for ($c = 1; $c < $size; $c++) {
                if ($matrix[$r][$c] === $matrix[$r][$c - 1]) {
                    $run++;
                } else {
                    if ($run >= 5) {
                        $penalty += 3 + ($run - 5);
                    }
                    $run = 1;
                }
            }
            if ($run >= 5) {
                $penalty += 3 + ($run - 5);
            }
        }

        for ($c = 0; $c < $size; $c++) {
            $run = 1;
            for ($r = 1; $r < $size; $r++) {
                if ($matrix[$r][$c] === $matrix[$r - 1][$c]) {
                    $run++;
                } else {
                    if ($run >= 5) {
                        $penalty += 3 + ($run - 5);
                    }
                    $run = 1;
                }
            }
            if ($run >= 5) {
                $penalty += 3 + ($run - 5);
            }
        }

        for ($r = 0; $r < $size - 1; $r++) {
            for ($c = 0; $c < $size - 1; $c++) {
                $val = $matrix[$r][$c];
                if ($matrix[$r + 1][$c] === $val && $matrix[$r][$c + 1] === $val && $matrix[$r + 1][$c + 1] === $val) {
                    $penalty += 3;
                }
            }
        }

        for ($r = 0; $r < $size; $r++) {
            for ($c = 0; $c <= $size - 11; $c++) {
                $slice = '';
                for ($k = 0; $k < 11; $k++) {
                    $slice .= $matrix[$r][$c + $k];
                }
                if ('10111010000' === $slice || '00001011101' === $slice) {
                    $penalty += 40;
                }
            }
        }

        for ($c = 0; $c < $size; $c++) {
            for ($r = 0; $r <= $size - 11; $r++) {
                $slice = '';
                for ($k = 0; $k < 11; $k++) {
                    $slice .= $matrix[$r + $k][$c];
                }
                if ('10111010000' === $slice || '00001011101' === $slice) {
                    $penalty += 40;
                }
            }
        }

        $dark_count = 0;
        for ($r = 0; $r < $size; $r++) {
            for ($c = 0; $c < $size; $c++) {
                if (1 === $matrix[$r][$c]) {
                    $dark_count++;
                }
            }
        }
        $total = $size * $size;
        $pct = ($dark_count / $total) * 100;
        $prev_5 = floor($pct / 5) * 5;
        $next_5 = ceil($pct / 5) * 5;
        $diff1 = abs($prev_5 - 50) / 5;
        $diff2 = abs($next_5 - 50) / 5;
        $penalty += min($diff1, $diff2) * 10;

        return $penalty;
    }

    public static function encode($text, $ec_level = self::EC_L) {
        $data_len = strlen($text);

        // Select minimal QR version (1 to 10)
        $version = 0;
        for ($v = 1; $v <= 10; $v++) {
            if (isset(self::$capacities[$v][$ec_level]) && $data_len <= self::$capacities[$v][$ec_level]) {
                $version = $v;
                break;
            }
        }

        if (0 === $version) {
            $version = 10;
        }

        $total_cw = self::$total_codewords[$version];
        $specs = self::$block_specs[$version][$ec_level];

        $total_data_cw = 0;
        foreach ($specs as $sp) {
            $total_data_cw += $sp[0] * $sp[1];
        }

        // 8-bit Byte Mode Header: Mode Indicator '0100' (4 bits) + Character Count (8 bits for V1-V9, 16 bits for V10)
        $bits = '0100';
        $bits .= str_pad(decbin($data_len), ($version < 10 ? 8 : 16), '0', STR_PAD_LEFT);

        for ($i = 0; $i < $data_len; $i++) {
            $bits .= str_pad(decbin(ord($text[$i])), 8, '0', STR_PAD_LEFT);
        }

        $max_bits = $total_data_cw * 8;
        if (strlen($bits) < $max_bits) {
            $terminator_len = min(4, $max_bits - strlen($bits));
            $bits .= str_repeat('0', $terminator_len);
        }

        while (strlen($bits) % 8 !== 0) {
            $bits .= '0';
        }

        $pad_bytes = array('11101100', '00010001'); // 0xEC, 0x11
        $pad_idx = 0;
        while (strlen($bits) < $max_bits) {
            $bits .= $pad_bytes[$pad_idx % 2];
            $pad_idx++;
        }

        $data_bytes = array();
        for ($i = 0; $i < strlen($bits); $i += 8) {
            $data_bytes[] = bindec(substr($bits, $i, 8));
        }

        // Divide into RS Blocks
        $data_blocks = array();
        $ec_blocks = array();
        $offset = 0;

        foreach ($specs as $sp) {
            $num_blocks = $sp[0];
            $data_len_block = $sp[1];
            $ec_len_block = $sp[2];

            for ($b = 0; $b < $num_blocks; $b++) {
                $block = array_slice($data_bytes, $offset, $data_len_block);
                $offset += $data_len_block;
                $data_blocks[] = $block;
                $ec_blocks[] = self::calculate_rs_block($block, $ec_len_block);
            }
        }

        // Interleave Data and Error Correction Codewords
        $final_codewords = array();
        $max_data_len = 0;
        foreach ($data_blocks as $b) {
            $max_data_len = max($max_data_len, count($b));
        }

        for ($i = 0; $i < $max_data_len; $i++) {
            foreach ($data_blocks as $b) {
                if ($i < count($b)) {
                    $final_codewords[] = $b[$i];
                }
            }
        }

        $max_ec_len = 0;
        foreach ($ec_blocks as $b) {
            $max_ec_len = max($max_ec_len, count($b));
        }

        for ($i = 0; $i < $max_ec_len; $i++) {
            foreach ($ec_blocks as $b) {
                if ($i < count($b)) {
                    $final_codewords[] = $b[$i];
                }
            }
        }

        $final_bits = '';
        foreach ($final_codewords as $cw) {
            $final_bits .= str_pad(decbin($cw), 8, '0', STR_PAD_LEFT);
        }

        // Remainder bits for versions 2-6
        $remainder_bits = array(1 => 0, 2 => 7, 3 => 7, 4 => 7, 5 => 7, 6 => 7, 7 => 0, 8 => 0, 9 => 0, 10 => 0);
        if (isset($remainder_bits[$version]) && $remainder_bits[$version] > 0) {
            $final_bits .= str_repeat('0', $remainder_bits[$version]);
        }

        $matrix_size = 17 + (4 * $version);
        $matrix = array_fill(0, $matrix_size, array_fill(0, $matrix_size, -1));

        // 1. Finder Patterns & Separators
        $finders = array(array(0, 0), array(0, $matrix_size - 7), array($matrix_size - 7, 0));
        foreach ($finders as $f) {
            $fr = $f[0];
            $fc = $f[1];
            for ($r = 0; $r < 7; $r++) {
                for ($c = 0; $c < 7; $c++) {
                    if (0 === $r || 6 === $r || 0 === $c || 6 === $c || ($r >= 2 && $r <= 4 && $c >= 2 && $c <= 4)) {
                        $matrix[$fr + $r][$fc + $c] = 1;
                    } else {
                        $matrix[$fr + $r][$fc + $c] = 0;
                    }
                }
            }
        }

        // Separators around Finder Patterns
        for ($i = 0; $i < 8; $i++) {
            if ($i < $matrix_size && 7 < $matrix_size) {
                $matrix[$i][7] = 0;
                $matrix[7][$i] = 0;
                $matrix[$i][$matrix_size - 8] = 0;
                $matrix[7][$matrix_size - 1 - $i] = 0;
                $matrix[$matrix_size - 8][$i] = 0;
                $matrix[$matrix_size - 1 - $i][7] = 0;
            }
        }

        // 2. Timing Patterns
        for ($i = 8; $i < $matrix_size - 8; $i++) {
            if ($matrix[6][$i] === -1) {
                $matrix[6][$i] = ($i % 2 === 0) ? 1 : 0;
            }
            if ($matrix[$i][6] === -1) {
                $matrix[$i][6] = ($i % 2 === 0) ? 1 : 0;
            }
        }

        // 3. Dark Module
        $matrix[(4 * $version) + 9][8] = 1;

        // 4. Alignment Patterns (Versions 2+)
        if (isset(self::$align_patterns[$version])) {
            $coords = self::$align_patterns[$version];
            foreach ($coords as $ar) {
                foreach ($coords as $ac) {
                    if ($matrix[$ar][$ac] !== -1) {
                        continue;
                    }
                    for ($dr = -2; $dr <= 2; $dr++) {
                        for ($dc = -2; $dc <= 2; $dc++) {
                            if (abs($dr) === 2 || abs($dc) === 2 || (0 === $dr && 0 === $dc)) {
                                $matrix[$ar + $dr][$ac + $dc] = 1;
                            } else {
                                $matrix[$ar + $dr][$ac + $dc] = 0;
                            }
                        }
                    }
                }
            }
        }

        // Reserve Format Information Areas
        for ($i = 0; $i < 9; $i++) {
            if ($matrix[8][$i] === -1) $matrix[8][$i] = -2;
            if ($matrix[$i][8] === -1) $matrix[$i][8] = -2;
        }
        for ($i = 0; $i < 8; $i++) {
            if ($matrix[8][$matrix_size - 1 - $i] === -1) $matrix[8][$matrix_size - 1 - $i] = -2;
            if ($matrix[$matrix_size - 1 - $i][8] === -1) $matrix[$matrix_size - 1 - $i][8] = -2;
        }

        // Place Data Bits in Up/Down 2-Column Zig-Zag
        $bit_idx = 0;
        $total_bit_len = strlen($final_bits);
        $col = $matrix_size - 1;
        $going_up = true;

        while ($col > 0) {
            if (6 === $col) {
                $col--;
            }

            for ($row_step = 0; $row_step < $matrix_size; $row_step++) {
                $row = $going_up ? ($matrix_size - 1 - $row_step) : $row_step;

                for ($c = 0; $c < 2; $c++) {
                    $curr_col = $col - $c;
                    if ($matrix[$row][$curr_col] === -1) {
                        $bit_val = ($bit_idx < $total_bit_len) ? (int)$final_bits[$bit_idx] : 0;
                        $matrix[$row][$curr_col] = $bit_val;
                        $bit_idx++;
                    }
                }
            }

            $going_up = !$going_up;
            $col -= 2;
        }

        // Select Best Mask Pattern (0-7)
        $best_mask = 0;
        $min_penalty = PHP_INT_MAX;
        $best_matrix = $matrix;

        for ($m_id = 0; $m_id < 8; $m_id++) {
            $trial = $matrix;

            for ($r = 0; $r < $matrix_size; $r++) {
                for ($c = 0; $c < $matrix_size; $c++) {
                    if ($trial[$r][$c] >= 0 && $matrix[$r][$c] !== -2) {
                        if (self::mask_cond($m_id, $r, $c)) {
                            $trial[$r][$c] ^= 1;
                        }
                    }
                }
            }

            $format_data = ($ec_level << 3) | $m_id;
            $rem = $format_data << 10;
            for ($i = 4; $i >= 0; $i--) {
                if (($rem >> ($i + 10)) & 1) {
                    $rem ^= (0x537 << $i);
                }
            }
            $format_bits = (($format_data << 10) | $rem) ^ 0x5412;

            for ($i = 0; $i < 15; $i++) {
                $mod = ($format_bits >> $i) & 1;
                if ($i < 6) {
                    $trial[$i][8] = $mod;
                } elseif ($i < 8) {
                    $trial[$i + 1][8] = $mod;
                } else {
                    $trial[$matrix_size - 15 + $i][8] = $mod;
                }

                if ($i < 8) {
                    $trial[8][$matrix_size - 1 - $i] = $mod;
                } elseif ($i < 9) {
                    $trial[8][15 - $i] = $mod;
                } else {
                    $trial[8][14 - $i] = $mod;
                }
            }

            $score = self::penalty_score($trial, $matrix_size);
            if ($score < $min_penalty) {
                $min_penalty = $score;
                $best_mask = $m_id;
                $best_matrix = $trial;
            }
        }

        for ($r = 0; $r < $matrix_size; $r++) {
            for ($c = 0; $c < $matrix_size; $c++) {
                $best_matrix[$r][$c] = (1 === $best_matrix[$r][$c]) ? 1 : 0;
            }
        }

        return $best_matrix;
    }
}
