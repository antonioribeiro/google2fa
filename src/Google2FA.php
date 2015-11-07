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

use Base32\Base32;
use PragmaRX\Google2FA\Support\Url;
use PragmaRX\Google2FA\Support\Str;
use PragmaRX\Google2FA\Exceptions\InvalidCharactersException;
use PragmaRX\Google2FA\Exceptions\SecretKeyTooShortException;
use PragmaRX\Google2FA\Contracts\Google2FA as Google2FAContract;

use SimpleSoftwareIO\QrCode\BaconQrCodeGenerator;
use BaconQrCode\Renderer\Image\Png;

class Google2FA implements Google2FAContract
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
		"A" => 0,   "B" => 1,
		"C" => 2,   "D" => 3,
		"E" => 4,   "F" => 5,
		"G" => 6,   "H" => 7,
		"I" => 8,   "J" => 9,
		"K" => 10,  "L" => 11,
		"M" => 12,  "N" => 13,
		"O" => 14,  "P" => 15,
		"Q" => 16,  "R" => 17,
		"S" => 18,  "T" => 19,
		"U" => 20,  "V" => 21,
		"W" => 22,  "X" => 23,
		"Y" => 24,  "Z" => 25,
		"2" => 26,  "3" => 27,
		"4" => 28,  "5" => 29,
		"6" => 30,  "7" => 31
	);

	/**
	 * Generate a digit secret key in base32 format.
	 *
	 * @param int $length
	 * @return string
	 */
	public function generateSecretKey($length = 16, $prefix = '')
	{
		$b32 = "234567QWERTYUIOPASDFGHJKLZXCVBNM";

		$secret = $prefix ? $this->toBase32($prefix) : '';

		for ($i = 0; $i < $length; $i++)
		{
			$secret .= $b32[$this->getRandomNumber()];
		}

		$this->validateSecret($secret);

		return $secret;
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

		$this->validateSecret($b32);

		$l  = strlen($b32);
		$n  = 0;
		$j  = 0;
		$binary = "";

		for ($i = 0; $i < $l; $i++)
		{
			$n = $n << 5;               // Move buffer left by 5 to make room
			$n = $n + static::$lut[$b32[$i]];   // Add value into buffer
			$j = $j + 5;                // Keep track of number of bits in buffer

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
			throw new SecretKeyTooShortException();
		}

		// Counter must be 64-bit int
		$bin_counter = pack('N*', 0, $counter);

		$hash = hash_hmac('sha1', $bin_counter, $key, true);

		return str_pad($this->oathTruncate($hash), static::OPT_LENGTH, '0', STR_PAD_LEFT);
	}

	/**
	 * Get the current one time password for a key.
	 *
	 * @param string $initalizationKey
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
			if (Str::equals($this->oathHotp($binarySeed, $ts), $key))
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
		$temp = unpack('N', substr($hash, $offset, 4));
		return substr($temp[1] & 0x7fffffff, -static::OPT_LENGTH);
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
		$url = $this->getQRCodeUrl($company, $holder, $secret);

		return Url::generateGoogleQRCodeUrl('https://chart.googleapis.com/', 'chart', 'chs=200x200&chld=M|0&cht=qr&chl=', $url);
	}

	/**
	 * Generates a QR code data url to display inline.
	 *
	 * @param $company
	 * @param $holder
	 * @param $secret
	 * @return string
	 */
	public function getQRCodeInline($company, $holder, $secret, $size = 100)
	{
		$qr = new BaconQrCodeGenerator(null, new Png);
		$url = $this->getQRCodeUrl($company, $holder, $secret);

		return 'data:image/png;base64,' . base64_encode($qr->margin(0)->size($size)->generate($url));
	}

	/**
	 * Creates a QR code url.
	 *
	 * @param $company
	 * @param $holder
	 * @param $secret
	 * @return string
	 */
	public function getQRCodeUrl($company, $holder, $secret)
	{
		return 'otpauth://totp/'.$company.':'.$holder.'?secret='.$secret.'&issuer='.$company.'';
	}

	/**
	 * Get a random number.
	 *
	 * @param $from
	 * @param $to
	 * @return int
	 */
	private function getRandomNumber($from = 0, $to = 31)
	{
		return mt_rand($from, $to);
	}

	/**
	 * Validate the secret.
	 *
	 * @param $b32
	 * @throws InvalidCharactersException
	 */
	private function validateSecret($b32)
	{
		if (!preg_match('/^[' . static::VALID_FOR_B32 . ']+$/', $b32, $match))
		{
			throw new InvalidCharactersException();
		}
	}

	/**
	 * Encode a string to Base32.
	 *
	 * @param $string
	 * @return mixed
	 */
	public function toBase32($string)
	{
		$encoded = Base32::encode($string);

		return str_replace('=', '', $encoded);
	}
}
