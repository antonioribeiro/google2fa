<?php

namespace PragmaRX\Google2FA\Contracts;

interface Google2FA
{
    /**
     * Generate a digit secret key in base32 format.
     *
     * @param int $length
     *
     * @return string
     */
    public function generateSecretKey($length = 16);

    /**
     * Returns the current Unix Timestamp devided by the KEY_REGENERATION
     * period.
     *
     * @return int
     **/
    public function getTimestamp();

    /**
     * Decodes a base32 string into a binary string.
     *
     * @param string $b32
     *
     * @throws InvalidCharactersException
     *
     * @return int
     */
    public function base32Decode($b32);

    /**
     * Takes the secret key and the timestamp and returns the one time
     * password.
     *
     * @param string $key     - Secret key in binary form.
     * @param int    $counter - Timestamp as returned by getTimestamp.
     *
     * @throws SecretKeyTooShortException
     *
     * @return string
     */
    public function oathHotp($key, $counter);

    /**
     * Get the current one time password for a key.
     *
     * @param string $initalizationKey
     *
     * @throws InvalidCharactersException
     * @throws SecretKeyTooShortException
     *
     * @return string
     */
    public function getCurrentOtp($initalizationKey);

    /**
     * Verifies a user inputted key against the current timestamp. Checks $window
     * keys either side of the timestamp.
     *
     * @param string $b32seed
     * @param string $key          - User specified key
     * @param int    $window
     * @param bool   $useTimeStamp
     *
     * @return bool
     **/
    public function verifyKey($b32seed, $key, $window = 4, $useTimeStamp = true);

    /**
     * Verifies a user inputted key against the current timestamp. Checks $window
     * keys either side of the timestamp, but ensures that the given key is newer than
     * the given oldTimestamp. Useful if you need to ensure that a single key cannot
     * be used twice.
     *
     * @param string $b32seed
     * @param string $key          - User specified key
     * @param int    $oldTimestamp - The timestamp from the last verified key
     * @param int    $window
     * @param bool   $useTimeStamp
     *
     * @return bool|int - false (not verified) or the timestamp of the verified key
     **/
    public function verifyKeyNewer($b32seed, $key, $oldTimestamp, $window = 4, $useTimeStamp = true);

    /**
     * Extracts the OTP from the SHA1 hash.
     *
     * @param string $hash
     *
     * @return int
     **/
    public function oathTruncate($hash);

    /**
     * Remove invalid chars from a base 32 string.
     *
     * @param $string
     *
     * @return mixed
     */
    public function removeInvalidChars($string);

    /**
     * Creates a Google QR code url.
     *
     * @param string $company
     * @param string $holder
     * @param string $secret
     * @param int    $size
     *
     * @return string
     */
    public function getQRCodeGoogleUrl($company, $holder, $secret, $size = 200);

    /**
     * Generates a QR code data url to display inline.
     *
     * @param string $company
     * @param string $holder
     * @param string $secret
     * @param int    $size
     * @param string $encoding Default to UTF-8
     *
     * @return string
     */
    public function getQRCodeInline($company, $holder, $secret, $size = 100, $encoding = 'utf-8');

    /**
     * Get the key regeneration time in seconds.
     *
     * @return int
     */
    public function getKeyRegenerationTime();
}
