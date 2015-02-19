<?php

namespace PragmaRX\Google2FA\Contracts;

interface Google2FA
{

	/**
	 * Generate a digit secret key in base32 format.
	 *
	 * @param int $length
	 * @return string
	 */
	public function generateSecretKey($length = 16);

	/**
	 * Returns the current Unix Timestamp devided by the KEY_REGENERATION
	 * period.
	 *
	 * @return integer
	 **/
	public function getTimestamp();

	/**
	 * Decodes a base32 string into a binary string.
	 *
	 * @param string $b32
	 * @throws InvalidCharactersException
	 * @return integer
	 */
	public function base32Decode($b32);

	/**
	 * Takes the secret key and the timestamp and returns the one time
	 * password.
	 *
	 * @param string $key - Secret key in binary form.
	 * @param integer $counter - Timestamp as returned by getTimestamp.
	 * @throws SecretKeyTooShortException
	 * @return string
	 */
	public function oathHotp($key, $counter);

	/**
	 * Get the current one time password for a key.
	 *
	 * @param string $initalizationKey
	 * @return string
	 * @throws InvalidCharactersException
	 * @throws SecretKeyTooShortException
	 */
	public function getCurrentOtp($initalizationKey);

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
	public function verifyKey($b32seed, $key, $window = 4, $useTimeStamp = true);

	/**
	 * Extracts the OTP from the SHA1 hash.
	 *
	 * @param string $hash
	 * @return integer
	 **/
	public function oathTruncate($hash);

	/**
	 * Remove invalid chars from a base 32 string.
	 *
	 * @param $string
	 * @return mixed
	 */
	public function removeInvalidChars($string);

	/**
	 * Creates a Google QR code url.
	 *
	 * @param $company
	 * @param $holder
	 * @param $secret
	 * @return string
	 */
	public function getQRCodeGoogleUrl($company, $holder, $secret);

}
