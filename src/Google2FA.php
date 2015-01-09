<?php

namespace PragmaRX\Google2FA;

/**
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * PHP Google two-factor authentication module.
 *
 * See http://www.idontplaydarts.com/2011/07/google-totp-two-factor-authentication-for-php/
 * for more details
 *
 * @author Phil (Orginal author of this class)
 *
 * Changes have been made in the original class to remove all static methods and, also,
 * provide some other methods.
 *
 * @package    Google2FA
 * @author     Antonio Carlos Ribeiro @ PragmaRX
 **/

use PragmaRX\Google2FA\Exceptions\InvalidCharactersException;
use PragmaRX\Google2FA\Exceptions\SecretKeyTooShortException;

class Google2FA
{

	/**
	 * Interval between key regeneration
	 */
	const KEY_REGENERATION = 30;

	/**
	 * Length of the Token generated.
	 *
	 */
	const OPT_LENGTH = 6;

	/**
	 * Characters valid for Base 32.
	 *
	 */
	const VALID_FOR_B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * Lookup needed for Base32 encoding.
	 *
	 * @var array
	 */
	private static $lut = array(
        "A" => 0,	"B" => 1,
        "C" => 2,	"D" => 3,
        "E" => 4,	"F" => 5,
        "G" => 6,	"H" => 7,
        "I" => 8,	"J" => 9,
        "K" => 10,	"L" => 11,
        "M" => 12,	"N" => 13,
        "O" => 14,	"P" => 15,
        "Q" => 16,	"R" => 17,
        "S" => 18,	"T" => 19,
        "U" => 20,	"V" => 21,
        "W" => 22,	"X" => 23,
        "Y" => 24,	"Z" => 25,
        "2" => 26,	"3" => 27,
        "4" => 28,	"5" => 29,
        "6" => 30,	"7" => 31
	);

	/**
	 * Generates a 16 digit secret key in base32 format.
	 *
	 * @return string
	 **/
	public function generateSecretKey($length = 16)
	{
		$b32 = "234567QWERTYUIOPASDFGHJKLZXCVBNM";

		$s = "";

		for ($i = 0; $i < $length; $i++)
		{
			$s .= $b32[rand(0,31)];
		}

		return $s;
	}

	/**
	 * Returns the current Unix Timestamp devided by the KEY_REGENERATION
	 * period.
	 *
	 * @return integer
	 **/
	public function getTimestamp()
	{
		return floor(microtime(true) / static::KEY_REGENERATION);
	}

	/**
	 * Decodes a base32 string into a binary string.
	 *
	 * @param string $b32
	 * @throws InvalidCharactersException
	 * @return integer
	 */
	public function base32Decode($b32)
	{
		$b32 = strtoupper($b32);

		if (!preg_match('/^['.static::VALID_FOR_B32.']+$/', $b32, $match))
		{
			throw new InvalidCharactersException('Invalid characters in the base32 string.');
		}

		$l 	= strlen($b32);
		$n	= 0;
		$j	= 0;
		$binary = "";

		for ($i = 0; $i < $l; $i++)
		{
			$n = $n << 5; 				// Move buffer left by 5 to make room
			$n = $n + static::$lut[$b32[$i]]; 	// Add value into buffer
			$j = $j + 5;				// Keep track of number of bits in buffer

			if ($j >= 8)
			{
				$j = $j - 8;
				$binary .= chr(($n & (0xFF << $j)) >> $j);
			}
		}

		return $binary;
	}

	/**
	 * Takes the secret key and the timestamp and returns the one time
	 * password.
	 *
	 * @param string $key - Secret key in binary form.
	 * @param integer $counter - Timestamp as returned by getTimestamp.
	 * @throws SecretKeyTooShortException
	 * @return string
	 */
	public function oathHotp($key, $counter)
	{
		if (strlen($key) < 8)
		{
			throw new SecretKeyTooShortException('Secret key is too short. Must be at least 16 base 32 characters');
		}

		// Counter must be 64-bit int
		$bin_counter = pack('N*', 0) . pack('N*', $counter);

		$hash = hash_hmac('sha1', $bin_counter, $key, true);

		return str_pad($this->oathTruncate($hash), static::OPT_LENGTH, '0', STR_PAD_LEFT);
	}

	/**
	 * Get the current one time password for a key.
	 *
	 * @param $initalizationKey
	 * @return string
	 * @throws InvalidCharactersException
	 * @throws SecretKeyTooShortException
	 */
	public function getCurrentOtp($initalizationKey)
	{
		$timestamp = $this->getTimestamp();

		$secretKey = $this->base32Decode($initalizationKey);

		return $this->oathHotp($secretKey, $timestamp);
	}

	/**
	 * Verifies a user inputted key against the current timestamp. Checks $window
	 * keys either side of the timestamp.
	 *
	 * @param string $b32seed
	 * @param string $key - User specified key
	 * @param integer $window
	 * @param boolean $useTimeStamp
	 * @return boolean
	 **/
	public function verifyKey($b32seed, $key, $window = 4, $useTimeStamp = true)
	{
		$timeStamp = $this->getTimestamp();

		if ($useTimeStamp !== true)
		{
			$timeStamp = (int)$useTimeStamp;
		}

		$binarySeed = $this->base32Decode($b32seed);

		for ($ts = $timeStamp - $window; $ts <= $timeStamp + $window; $ts++)
		{
			if ($this->oathHotp($binarySeed, $ts) == $key)
			{
				return true;
			}
		}

		return false;
	}

	/**
	 * Extracts the OTP from the SHA1 hash.
	 *
	 * @param string $hash
	 * @return integer
	 **/
	public function oathTruncate($hash)
	{
		$offset = ord($hash[19]) & 0xf;

		return (
			((ord($hash[$offset+0]) & 0x7f) << 24 ) |
			((ord($hash[$offset+1]) & 0xff) << 16 ) |
			((ord($hash[$offset+2]) & 0xff) << 8 ) |
			(ord($hash[$offset+3]) & 0xff)
		) % pow(10, static::OPT_LENGTH);
	}

	/**
	 * Remove invalid chars from a base 32 string.
	 *
	 * @param $string
	 * @return mixed
	 */
	public function removeInvalidChars($string)
	{
		return preg_replace('/[^'.static::VALID_FOR_B32.']/', '', $string);
	}

	/**
	 * Creates a Google QR code url.
	 *
	 * @param $company
	 * @param $holder
	 * @param $secret
	 * @return string
	 */
	public function getQRCodeGoogleUrl($company, $holder, $secret)
	{
		$url = 'otpauth://totp/'.$company.':'.$holder.'?secret='.$secret.'&issuer='.$company.'';

		return 'https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl='.urlencode($url).'';
	}

}
