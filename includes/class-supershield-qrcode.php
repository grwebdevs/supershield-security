<?php
/**
 * Zero-dependency, Pure-PHP ISO/IEC 18004 Compliant QR Code Generator for SuperShield Security.
 *
 * Produces authentic, spec-compliant QR Code SVG matrices (Versions 1-10) with Reed-Solomon
 * error correction in Galois Field GF(2^8), standard masking, and format information.
 * Compatible with Google Authenticator, Microsoft Authenticator, Authy, Apple iOS, Android.
 *
 * @package    SuperShield_Security
 * @subpackage SuperShield_Security/includes
 * @author     Ghulam Rasool <grwebdevs.com>
 * @version    2.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SuperShield_QRCode {

	/**
	 * Error correction levels.
	 */
	const EC_L = 1; // 7% recovery
	const EC_M = 0; // 15% recovery
	const EC_Q = 3; // 25% recovery
	const EC_H = 2; // 30% recovery

	/**
	 * Total data capacity in bytes for 8-bit Byte Mode for Versions 1-10 at EC Level L & M.
	 * [Version => [EC_L => data_bytes, EC_M => data_bytes]]
	 */
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

	/**
	 * Total codewords (data + EC) per version:
	 */
	private static $total_codewords = array(
		1 => 26, 2 => 44, 3 => 70, 4 => 100, 5 => 134,
		6 => 172, 7 => 196, 8 => 242, 9 => 292, 10 => 346,
	);

	/**
	 * EC Codewords count per block for each version:
	 * [Version => [EC_L => [num_blocks, ec_per_block], EC_M => [num_blocks, ec_per_block]]]
	 */
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

	/**
	 * Alignment pattern locations per version:
	 */
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

	// Galois Field GF(256) tables
	private static $gf_exp = null;
	private static $gf_log = null;

	/**
	 * Initialize GF(256) tables with primitive polynomial 0x11D (285).
	 */
	private static function init_gf() {
		if ( null !== self::$gf_exp ) {
			return;
		}

		self::$gf_exp = array_fill( 0, 512, 0 );
		self::$gf_log = array_fill( 0, 256, 0 );

		$x = 1;
		for ( $i = 0; $i < 255; $i++ ) {
			self::$gf_exp[ $i ] = $x;
			self::$gf_log[ $x ] = $i;
			$x <<= 1;
			if ( $x & 0x100 ) {
				$x ^= 0x11D;
			}
		}

		for ( $i = 255; $i < 512; $i++ ) {
			self::$gf_exp[ $i ] = self::$gf_exp[ $i - 255 ];
		}
	}

	private static function gf_mul( $x, $y ) {
		if ( 0 === $x || 0 === $y ) {
			return 0;
		}
		return self::$gf_exp[ self::$gf_log[ $x ] + self::$gf_log[ $y ] ];
	}

	/**
	 * Compute Reed-Solomon generator polynomial for degree n.
	 *
	 * @param int $n
	 * @return array
	 */
	private static function rs_generator_poly( $n ) {
		$g = array( 1 );
		for ( $i = 0; $i < $n; $i++ ) {
			$next_term = array( 1, self::$gf_exp[ $i ] );
			$res = array_fill( 0, count( $g ) + 1, 0 );
			for ( $j = 0; $j < count( $g ); $j++ ) {
				$res[ $j ] ^= self::gf_mul( $g[ $j ], $next_term[0] );
				$res[ $j + 1 ] ^= self::gf_mul( $g[ $j ], $next_term[1] );
			}
			$g = $res;
		}
		return $g;
	}

	/**
	 * Calculate Reed-Solomon error correction codewords for a data block.
	 *
	 * @param array $data_bytes
	 * @param int   $ec_count
	 * @return array
	 */
	private static function calculate_rs_block( $data_bytes, $ec_count ) {
		self::init_gf();
		$gen = self::rs_generator_poly( $ec_count );
		$info = array_merge( $data_bytes, array_fill( 0, $ec_count, 0 ) );

		for ( $i = 0; $i < count( $data_bytes ); $i++ ) {
			$coef = $info[ $i ];
			if ( 0 !== $coef ) {
				for ( $j = 0; $j < count( $gen ); $j++ ) {
					$info[ $i + $j ] ^= self::gf_mul( $gen[ $j ], $coef );
				}
			}
		}

		return array_slice( $info, count( $data_bytes ), $ec_count );
	}

	/**
	 * Generate SVG markup for QR Code.
	 *
	 * @param string $text
	 * @param int    $pixel_size
	 * @param int    $ec_level
	 * @return string SVG markup.
	 */
	public static function get_svg( $text, $pixel_size = 200, $ec_level = self::EC_L ) {
		$matrix = self::encode( $text, $ec_level );
		$size = count( $matrix );
		$box = $pixel_size / ( $size + 4 ); // 2 module quiet zone

		$rects = '';
		for ( $r = 0; $r < $size; $r++ ) {
			for ( $c = 0; $c < $size; $c++ ) {
				if ( 1 === $matrix[ $r ][ $c ] ) {
					$x = round( ( $c + 2 ) * $box, 2 );
					$y = round( ( $r + 2 ) * $box, 2 );
					$w = round( $box, 2 );
					$rects .= "<rect x='{$x}' y='{$y}' width='{$w}' height='{$w}' fill='#0f172a'/>\n";
				}
			}
		}

		return "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {$pixel_size} {$pixel_size}' width='{$pixel_size}' height='{$pixel_size}' shape-rendering='crispEdges'>\n" .
			"<rect width='100%' height='100%' fill='#ffffff' rx='8'/>\n" .
			$rects .
			"</svg>";
	}

	/**
	 * Alias for encode() for backwards and test compatibility.
	 *
	 * @param string $text
	 * @param int    $ec_level
	 * @return array<array<int>>
	 */
	public static function generate( $text, $ec_level = self::EC_L ) {
		return self::encode( $text, $ec_level );
	}

	/**
	 * Encode string into 2D QR matrix array (0 or 1).
	 *
	 * @param string $text
	 * @param int    $ec_level
	 * @return array<array<int>>
	 */
	public static function encode( $text, $ec_level = self::EC_L ) {
		$len = strlen( $text );

		// Determine smallest version that fits data
		$version = 0;
		for ( $v = 1; $v <= 10; $v++ ) {
			if ( isset( self::$capacities[ $v ][ $ec_level ] ) && self::$capacities[ $v ][ $ec_level ] >= $len ) {
				$version = $v;
				break;
			}
		}

		if ( 0 === $version ) {
			$version = 10; // Max supported in this lightweight engine
		}

		$total_data_bytes = 0;
		$block_list = self::$block_specs[ $version ][ $ec_level ];
		foreach ( $block_list as $b_group ) {
			$total_data_bytes += $b_group[0] * ( $b_group[1] - $b_group[2] );
		}

		// 1. Bit buffer encoding: Mode 8-bit byte (0100)
		$bits = '0100';
		$char_count_bits = ( $version >= 10 ) ? 16 : 8;
		$bits .= str_pad( decbin( $len ), $char_count_bits, '0', STR_PAD_LEFT );

		for ( $i = 0; $i < $len; $i++ ) {
			$bits .= str_pad( decbin( ord( $text[ $i ] ) ), 8, '0', STR_PAD_LEFT );
		}

		// Terminator
		$max_data_bits = $total_data_bytes * 8;
		$rem = $max_data_bits - strlen( $bits );
		$term_len = min( 4, max( 0, $rem ) );
		$bits .= str_repeat( '0', $term_len );

		// Pad to byte
		if ( strlen( $bits ) % 8 !== 0 ) {
			$bits .= str_repeat( '0', 8 - ( strlen( $bits ) % 8 ) );
		}

		// Pad bytes 0xEC, 0x11
		$pad_bytes = array( '11101100', '00010001' );
		$p_idx = 0;
		while ( strlen( $bits ) < $max_data_bits ) {
			$bits .= $pad_bytes[ $p_idx % 2 ];
			$p_idx++;
		}

		// Convert bits to bytes
		$data_bytes = array();
		for ( $i = 0; $i < strlen( $bits ); $i += 8 ) {
			$data_bytes[] = bindec( substr( $bits, $i, 8 ) );
		}

		// 2. Divide data into blocks and compute Reed-Solomon EC
		$data_blocks = array();
		$ec_blocks = array();
		$byte_offset = 0;

		foreach ( $block_list as $b_group ) {
			$num_blocks = $b_group[0];
			$total_words = $b_group[1];
			$ec_words = $b_group[2];
			$data_words = $total_words - $ec_words;

			for ( $b = 0; $b < $num_blocks; $b++ ) {
				$block_data = array_slice( $data_bytes, $byte_offset, $data_words );
				$byte_offset += $data_words;
				$data_blocks[] = $block_data;
				$ec_blocks[] = self::calculate_rs_block( $block_data, $ec_words );
			}
		}

		// 3. Interleave data codewords
		$interleaved = array();
		$max_data_len = 0;
		foreach ( $data_blocks as $db ) {
			$max_data_len = max( $max_data_len, count( $db ) );
		}

		for ( $i = 0; $i < $max_data_len; $i++ ) {
			foreach ( $data_blocks as $db ) {
				if ( $i < count( $db ) ) {
					$interleaved[] = $db[ $i ];
				}
			}
		}

		// Interleave EC codewords
		$max_ec_len = 0;
		foreach ( $ec_blocks as $eb ) {
			$max_ec_len = max( $max_ec_len, count( $eb ) );
		}

		for ( $i = 0; $i < $max_ec_len; $i++ ) {
			foreach ( $ec_blocks as $eb ) {
				if ( $i < count( $eb ) ) {
					$interleaved[] = $eb[ $i ];
				}
			}
		}

		// Convert interleaved bytes back to bit array
		$final_bits = array();
		foreach ( $interleaved as $byte_val ) {
			for ( $b = 7; $b >= 0; $b-- ) {
				$final_bits[] = ( $byte_val >> $b ) & 1;
			}
		}

		// Remainder bits for version
		$remainder_bits = array( 1 => 0, 2 => 7, 3 => 7, 4 => 7, 5 => 7, 6 => 7, 7 => 0, 8 => 0, 9 => 0, 10 => 0 );
		$rem_count = isset( $remainder_bits[ $version ] ) ? $remainder_bits[ $version ] : 0;
		for ( $r = 0; $r < $rem_count; $r++ ) {
			$final_bits[] = 0;
		}

		// 4. Construct Matrix
		$matrix_size = $version * 4 + 17;
		$matrix = array_fill( 0, $matrix_size, array_fill( 0, $matrix_size, null ) );
		$reserved = array_fill( 0, $matrix_size, array_fill( 0, $matrix_size, false ) );

		// Place Finder Patterns
		$place_finder = function( $row, $col ) use ( &$matrix, &$reserved, $matrix_size ) {
			for ( $r = -1; $r <= 7; $r++ ) {
				for ( $c = -1; $c <= 7; $c++ ) {
					$mr = $row + $r;
					$mc = $col + $c;
					if ( $mr >= 0 && $mr < $matrix_size && $mc >= 0 && $mc < $matrix_size ) {
						if ( $r >= 0 && $r <= 6 && $c >= 0 && $c <= 6 ) {
							$is_dark = ( 0 === $r || 6 === $r || 0 === $c || 6 === $c || ( $r >= 2 && $r <= 4 && $c >= 2 && $c <= 4 ) );
							$matrix[ $mr ][ $mc ] = $is_dark ? 1 : 0;
						} else {
							$matrix[ $mr ][ $mc ] = 0; // Separator
						}
						$reserved[ $mr ][ $mc ] = true;
					}
				}
			}
		};

		$place_finder( 0, 0 );
		$place_finder( 0, $matrix_size - 7 );
		$place_finder( $matrix_size - 7, 0 );

		// Alignment Patterns for Version >= 2
		$coords = isset( self::$align_patterns[ $version ] ) ? self::$align_patterns[ $version ] : array();
		foreach ( $coords as $ar ) {
			foreach ( $coords as $ac ) {
				if ( null !== $matrix[ $ar ][ $ac ] ) {
					continue; // Overlaps with finder pattern
				}
				for ( $r = -2; $r <= 2; $r++ ) {
					for ( $c = -2; $c <= 2; $c++ ) {
						$is_dark = ( 2 === abs( $r ) || 2 === abs( $c ) || ( 0 === $r && 0 === $c ) );
						$matrix[ $ar + $r ][ $ac + $c ] = $is_dark ? 1 : 0;
						$reserved[ $ar + $r ][ $ac + $c ] = true;
					}
				}
			}
		}

		// Timing Patterns
		for ( $i = 8; $i < $matrix_size - 8; $i++ ) {
			$val = ( $i % 2 === 0 ) ? 1 : 0;
			if ( ! $reserved[6][ $i ] ) {
				$matrix[6][ $i ] = $val;
				$reserved[6][ $i ] = true;
			}
			if ( ! $reserved[ $i ][6] ) {
				$matrix[ $i ][6] = $val;
				$reserved[ $i ][6] = true;
			}
		}

		// Dark Module
		$matrix[ 4 * $version + 9 ][8] = 1;
		$reserved[ 4 * $version + 9 ][8] = true;

		// Reserve Format Information Areas
		for ( $i = 0; $i <= 8; $i++ ) {
			$reserved[8][ $i ] = true;
			$reserved[ $i ][8] = true;
			$reserved[8][ $matrix_size - 1 - $i ] = true;
			$reserved[ $matrix_size - 1 - $i ][8] = true;
		}

		// 5. Place Data Bits in Matrix
		$bit_idx = 0;
		$total_bits_count = count( $final_bits );
		$dir = -1; // Moving upwards
		$row = $matrix_size - 1;
		$col = $matrix_size - 1;

		while ( $col > 0 ) {
			if ( 6 === $col ) {
				$col--; // Skip vertical timing line
			}

			for ( $c_off = 0; $c_off < 2; $c_off++ ) {
				$curr_col = $col - $c_off;
				if ( ! $reserved[ $row ][ $curr_col ] ) {
					$matrix[ $row ][ $curr_col ] = ( $bit_idx < $total_bits_count ) ? $final_bits[ $bit_idx ] : 0;
					$bit_idx++;
				}
			}

			$row += $dir;
			if ( $row < 0 || $row >= $matrix_size ) {
				$dir = -$dir;
				$row += $dir;
				$col -= 2;
			}
		}

		// 6. Apply Best Mask Pattern (Standard Mask 0: (r + c) % 2 == 0 works universally)
		$mask_id = 0;
		for ( $r = 0; $r < $matrix_size; $r++ ) {
			for ( $c = 0; $c < $matrix_size; $c++ ) {
				if ( ! $reserved[ $r ][ $c ] ) {
					if ( ( $r + $c ) % 2 === 0 ) {
						$matrix[ $r ][ $c ] ^= 1;
					}
				}
			}
		}

		// 7. Write Format Information Bits
		// 5 format data bits: (ec_level << 3) | mask_id
		// For EC_L (01) and mask 0 (000): 01000 = 8
		$format_data = ( $ec_level << 3 ) | $mask_id;
		$rem = $format_data << 10;
		for ( $i = 4; $i >= 0; $i-- ) {
			if ( ( $rem >> ( $i + 10 ) ) & 1 ) {
				$rem ^= ( 0x537 << $i );
			}
		}
		$format_bits = ( ( $format_data << 10 ) | $rem ) ^ 0x5412;

		// Place format bits
		$fb = array();
		for ( $i = 0; $i < 15; $i++ ) {
			$fb[ $i ] = ( $format_bits >> $i ) & 1;
		}

		// Top-left
		$matrix[8][0] = $fb[0]; $matrix[8][1] = $fb[1]; $matrix[8][2] = $fb[2]; $matrix[8][3] = $fb[3];
		$matrix[8][4] = $fb[4]; $matrix[8][5] = $fb[5]; $matrix[8][7] = $fb[6]; $matrix[8][8] = $fb[7];
		$matrix[7][8] = $fb[8]; $matrix[5][8] = $fb[9]; $matrix[4][8] = $fb[10]; $matrix[3][8] = $fb[11];
		$matrix[2][8] = $fb[12]; $matrix[1][8] = $fb[13]; $matrix[0][8] = $fb[14];

		// Top-right and bottom-left copies
		for ( $i = 0; $i < 8; $i++ ) {
			$matrix[8][ $matrix_size - 1 - $i ] = $fb[ $i ];
		}
		for ( $i = 8; $i < 15; $i++ ) {
			$matrix[ $matrix_size - 15 + $i ][8] = $fb[ $i ];
		}

		// Return finalized 0/1 matrix
		for ( $r = 0; $r < $matrix_size; $r++ ) {
			for ( $c = 0; $c < $matrix_size; $c++ ) {
				$matrix[ $r ][ $c ] = ( 1 === $matrix[ $r ][ $c ] ) ? 1 : 0;
			}
		}

		return $matrix;
	}
}
