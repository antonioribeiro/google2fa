<?php

namespace PragmaRX\Google2FA;

/*
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
use BaconQrCode\Writer;
use PragmaRX\Google2FA\Support\Url;
use BaconQrCode\Renderer\Image\Png;
use PragmaRX\Google2FA\Contracts\Google2FA as Google2FAContract;
use PragmaRX\Google2FA\Exceptions\IncompatibleWithGoogleAuthenticatorException;
use PragmaRX\Google2FA\Exceptions\InvalidCharactersException;
use PragmaRX\Google2FA\Exceptions\SecretKeyTooShortException;

class Google2FA implements Google2FAContract
{
    /**
     * Characters valid for Base 32.
     */
    const VALID_FOR_B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /**
     * Length of the Token generated.
     */
    private $oneTimePasswordLength = 6;

    /**
     * Interval between key regeneration.
     */
    private $keyRegeneration = 30;

    /**
     * Enforce Google Authenticator compatibility.
     */
    private $enforceGoogleAuthenticatorCompatibility = true;

    /**
     * Secret
     */
    private $secret;

    /**
     * Window
     */
    private $window = 1; // Keys will be valid for 60 seconds

    /**
     * Check if all secret key characters are valid.
     *
     * @param $b32
     *
     * @throws InvalidCharactersException
     */
    private function checkForValidCharacters($b32)
    {
        if (!preg_match('/^['.static::VALID_FOR_B32.']+$/', $b32, $match)) {
            throw new InvalidCharactersException();
        }
    }

    /**
     * Check if the secret key is compatible with Google Authenticator.
     *
     * @param $b32
     *
     * @throws IncompatibleWithGoogleAuthenticatorException
     */
    private function checkGoogleAuthenticatorCompatibility($b32)
    {
        if ($this->enforceGoogleAuthenticatorCompatibility && ((strlen($b32) & (strlen($b32) - 1)) !== 0)) {
            throw new IncompatibleWithGoogleAuthenticatorException();
        }
    }

    /**
     * Generate a digit secret key in base32 format.
     *
     * @param int $length
     *
     * @return string
     */
    public function generateSecretKey($length = 16, $prefix = '')
    {
        $b32 = '234567QWERTYUIOPASDFGHJKLZXCVBNM';

        $secret = $prefix ? $this->toBase32($prefix) : '';

        for ($i = 0; $i < $length; $i++) {
            $secret .= $b32[$this->getRandomNumber()];
        }

        $this->validateSecret($secret);

        return $secret;
    }

    /**
     * Get key regeneration.
     *
     * @return mixed
     */
    public function getKeyRegeneration()
    {
        return $this->keyRegeneration;
    }

    /**
     * Get OTP length.
     *
     * @return mixed
     */
    public function getOneTimePasswordLength()
    {
        return $this->oneTimePasswordLength;
    }

    /**
     * Get secret.
     *
     * @return mixed
     */
    public function getSecret($secret = null)
    {
        return
            is_null($secret)
            ? $this->secret
            : $secret
        ;
    }

    /**
     * Returns the current Unix Timestamp divided by the $keyRegeneration
     * period.
     *
     * @return int
     **/
    public function getTimestamp()
    {
        return floor(microtime(true) / $this->keyRegeneration);
    }

    /**
     * Decodes a base32 string into a binary string.
     *
     * @param string $b32
     *
     * @throws InvalidCharactersException
     *
     * @return int
     */
    public function base32Decode($b32)
    {
        $b32 = strtoupper($b32);

        $this->validateSecret($b32);

        return Base32::decode($b32);
    }

    /**
     * Get the OTP window.
     *
     * @return mixed
     */
    public function getWindow($window = null)
    {
        return
            is_null($window)
                ? $this->window
                : $window
        ;
    }

    /**
     * Get/use a starting timestamp for key verification.
     *
     * @param $useTimestamp
     * @return int
     */
    private function makeStartingTimestamp($useTimestamp)
    {
        if ($useTimestamp !== true) {
            return (int) $useTimestamp;
        }

        return $this->getTimestamp();
    }

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
    public function oathHotp($key, $counter)
    {
        if (strlen($key) < 8) {
            throw new SecretKeyTooShortException();
        }

        // Counter must be 64-bit int
        $bin_counter = pack('N*', 0, $counter);

        $hash = hash_hmac('sha1', $bin_counter, $key, true);

        return str_pad($this->oathTruncate($hash), $this->getOneTimePasswordLength(), '0', STR_PAD_LEFT);
    }

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
    public function getCurrentOtp($initalizationKey)
    {
        $timestamp = $this->getTimestamp();

        $secretKey = $this->base32Decode($initalizationKey);

        return $this->oathHotp($secretKey, $timestamp);
    }

    /**
     * Setter for the enforce Google Authenticator compatibility property.
     *
     * @param mixed $enforceGoogleAuthenticatorCompatibility
     *
     * @return $this
     */
    public function setEnforceGoogleAuthenticatorCompatibility($enforceGoogleAuthenticatorCompatibility)
    {
        $this->enforceGoogleAuthenticatorCompatibility = $enforceGoogleAuthenticatorCompatibility;

        return $this;
    }

    /**
     * Set key regeneration.
     *
     * @param mixed $keyRegeneration
     */
    public function setKeyRegeneration($keyRegeneration)
    {
        $this->keyRegeneration = $keyRegeneration;
    }

    /**
     * Set OTP length.
     *
     * @param mixed $oneTimePasswordLength
     */
    public function setOneTimePasswordLength($oneTimePasswordLength)
    {
        $this->oneTimePasswordLength = $oneTimePasswordLength;
    }

    /**
     * Set secret.
     *
     * @param mixed $secret
     */
    public function setSecret($secret)
    {
        $this->secret = $secret;
    }

    /**
     * Set the OTP window.
     *
     * @param mixed $window
     */
    public function setWindow($window)
    {
        $this->window = $window;
    }

    /**
     * Verifies a user inputted key against the current timestamp. Checks $window
     * keys either side of the timestamp.
     *
     * @param string   $key - User specified key
     * @param null|string   $secret
     * @param null|int      $window
     * @param bool|int $useTimestamp
     * @param null|int $oldTimestamp
     * @return bool|int
     */
    public function verify($key, $secret = null, $window = null, $useTimestamp = true, $oldTimestamp = null)
    {
        return $this->verifyKey(
            $this->getSecret($secret),
            $key,
            $window,
            $useTimestamp,
            $oldTimestamp
        );
    }

    /**
     * Verifies a user inputted key against the current timestamp. Checks $window
     * keys either side of the timestamp.
     *
     * @param string   $secret
     * @param string   $key - User specified key
     * @param null|int $window
     * @param bool|int $useTimestamp
     * @param null|int $oldTimestamp
     * @return bool|int
     */
    public function verifyKey($secret, $key, $window = null, $useTimestamp = true, $oldTimestamp = null)
    {
        $timestamp = $this->makeStartingTimestamp($useTimestamp);

        $binarySeed = $this->base32Decode($secret);

        $ts = is_null($oldTimestamp)
                ? $timestamp - $this->getWindow($window)
                : max($timestamp - $this->getWindow($window), $oldTimestamp);

        for (; $ts <= $timestamp + $this->getWindow($window); $ts++) {
            if (hash_equals($this->oathHotp($binarySeed, $ts), $key)) {
                return
                    is_null($oldTimestamp)
                        ? true
                        : $ts
                ;
            }
        }

        return false;
    }

    /**
     * Verifies a user inputted key against the current timestamp. Checks $window
     * keys either side of the timestamp, but ensures that the given key is newer than
     * the given oldTimestamp. Useful if you need to ensure that a single key cannot
     * be used twice.
     *
     * @param string $secret
     * @param string $key          - User specified key
     * @param int    $oldTimestamp - The timestamp from the last verified key
     * @param int    $window
     * @param bool   $useTimestamp
     *
     * @return bool|int - false (not verified) or the timestamp of the verified key
     **/
    public function verifyKeyNewer($secret, $key, $oldTimestamp, $window = null, $useTimestamp = true)
    {
        return $this->verifyKey($secret, $key, $window, $useTimestamp, $oldTimestamp);
    }

    /**
     * Extracts the OTP from the SHA1 hash.
     *
     * @param string $hash
     *
     * @return int
     **/
    public function oathTruncate($hash)
    {
        $offset = ord($hash[19]) & 0xf;
        $temp = unpack('N', substr($hash, $offset, 4));

        return substr($temp[1] & 0x7fffffff, -$this->getOneTimePasswordLength());
    }

    /**
     * Remove invalid chars from a base 32 string.
     *
     * @param $string
     *
     * @return mixed
     */
    public function removeInvalidChars($string)
    {
        return preg_replace('/[^'.static::VALID_FOR_B32.']/', '', $string);
    }

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
    public function getQRCodeGoogleUrl($company, $holder, $secret, $size = 200)
    {
        $url = $this->getQRCodeUrl($company, $holder, $secret);

        return Url::generateGoogleQRCodeUrl('https://chart.googleapis.com/', 'chart', 'chs='.$size.'x'.$size.'&chld=M|0&cht=qr&chl=', $url);
    }

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
    public function getQRCodeInline($company, $holder, $secret, $size = 200, $encoding = 'utf-8')
    {
        $url = $this->getQRCodeUrl($company, $holder, $secret);

        $renderer = new Png();
        $renderer->setWidth($size);
        $renderer->setHeight($size);

        $writer = new Writer($renderer);
        $data = $writer->writeString($url, $encoding);

        return 'data:image/png;base64,'.base64_encode($data);
    }

    /**
     * Creates a QR code url.
     *
     * @param $company
     * @param $holder
     * @param $secret
     *
     * @return string
     */
    public function getQRCodeUrl($company, $holder, $secret)
    {
        return 'otpauth://totp/'.rawurlencode($company).':'.$holder.'?secret='.$secret.'&issuer='.rawurlencode($company).'';
    }

    /**
     * Get a random number.
     *
     * @param $from
     * @param $to
     *
     * @return int
     */
    private function getRandomNumber($from = 0, $to = 31)
    {
        return random_int($from, $to);
    }

    /**
     * Validate the secret.
     *
     * @param $b32
     */
    private function validateSecret($b32)
    {
        $this->checkForValidCharacters($b32);

        $this->checkGoogleAuthenticatorCompatibility($b32);
    }

    /**
     * Encode a string to Base32.
     *
     * @param $string
     *
     * @return mixed
     */
    public function toBase32($string)
    {
        $encoded = Base32::encode($string);

        return str_replace('=', '', $encoded);
    }

    /**
     * Get the key regeneration time in seconds.
     *
     * @return int
     */
    public function getKeyRegenerationTime()
    {
        return $this->keyRegeneration;
    }
}
