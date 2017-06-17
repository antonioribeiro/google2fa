<?php

namespace PragmaRX\Google2FA\Contracts;

interface Google2FA
{
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
     * Returns the current Unix Timestamp devided by the KEY_REGENERATION
     * period.
     *
     * @return int
     **/
    public function getTimestamp();

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
     * Extracts the OTP from the SHA1 hash.
     *
     * @param string $hash
     *
     * @return int
     **/
    public function oathTruncate($hash);

    /**
     * Verifies a user inputted key against the current timestamp. Checks $window
     * keys either side of the timestamp.
     *
     * @param string $secret
     * @param string $key          - User specified key
     * @param int    $window
     * @param bool   $useTimeStamp
     *
     * @return bool
     **/
    public function verifyKey($secret, $key, $window = null, $useTimeStamp = true);
}
