<?php

namespace PragmaRX\Google2FA;

use PragmaRX\Google2FA\Exceptions\IncompatibleWithGoogleAuthenticatorException;
use PragmaRX\Google2FA\Exceptions\InvalidAlgorithmException;
use PragmaRX\Google2FA\Exceptions\InvalidCharactersException;
use PragmaRX\Google2FA\Exceptions\SecretKeyTooShortException;
use PragmaRX\Google2FA\Support\Base32;
use PragmaRX\Google2FA\Support\Constants;
use PragmaRX\Google2FA\Support\QRCode;

class Google2FA
{
    use Base32;
    use QRCode;

    /**
     * Algorithm.
     */
    protected string $algorithm = Constants::SHA1;

    /**
     * Length of the Token generated.
     */
    protected int $oneTimePasswordLength = 6;

    /**
     * Interval between key regeneration.
     */
    protected int $keyRegeneration = 30;

    /**
     * Secret.
     */
    protected string $secret;

    /**
     * Window.
     */
    protected int $window = 1; // Keys will be valid for 60 seconds

    /**
     * Find a valid One Time Password.
     *
     * @param  string  $secret
     * @param  string  $key
     *
     * @throws IncompatibleWithGoogleAuthenticatorException
     * @throws InvalidCharactersException
     * @throws SecretKeyTooShortException
     */
    public function findValidOTP(
        #[\SensitiveParameter] string $secret,
        #[\SensitiveParameter] string $key,
        ?int $window,
        int $startingTimestamp,
        int $timestamp,
        ?int $oldTimestamp = null
    ): bool|int {
        for (;
            $startingTimestamp <= $timestamp + $this->getWindow($window);
            $startingTimestamp++
        ) {
            if (
                hash_equals($this->oathTotp($secret, $startingTimestamp), (string) $key)
            ) {
                return is_null($oldTimestamp)
                    ? true
                    : $startingTimestamp;
            }
        }

        return false;
    }

    /**
     * Generate the HMAC OTP.
     *
     * @param  string  $secret
     */
    protected function generateHotp(
        #[\SensitiveParameter] string $secret,
        int $counter
    ): string {
        return hash_hmac(
            $this->getAlgorithm(),
            pack('N*', 0, $counter), // Counter must be 64-bit int
            $secret,
            true
        );
    }

    /**
     * Generate a digit secret key in base32 format.
     *
     *
     * @throws InvalidCharactersException
     * @throws SecretKeyTooShortException
     * @throws IncompatibleWithGoogleAuthenticatorException
     */
    public function generateSecretKey(int $length = 16, string $prefix = ''): string
    {
        return $this->generateBase32RandomKey($length, $prefix);
    }

    /**
     * Get the current one time password for a key.
     *
     * @param  string  $secret
     *
     * @throws IncompatibleWithGoogleAuthenticatorException
     * @throws InvalidCharactersException
     * @throws SecretKeyTooShortException
     */
    public function getCurrentOtp(
        #[\SensitiveParameter] string $secret
    ): string {
        return $this->oathTotp($secret, $this->getTimestamp());
    }

    /**
     * Get the HMAC algorithm.
     */
    public function getAlgorithm(): string
    {
        return $this->algorithm;
    }

    /**
     * Get key regeneration.
     */
    public function getKeyRegeneration(): int
    {
        return $this->keyRegeneration;
    }

    /**
     * Get OTP length.
     */
    public function getOneTimePasswordLength(): int
    {
        return $this->oneTimePasswordLength;
    }

    /**
     * Get secret.
     *
     * @param  string|null  $secret
     */
    public function getSecret(
        #[\SensitiveParameter] ?string $secret = null
    ): string {
        return is_null($secret) ? $this->secret : $secret;
    }

    /**
     * Returns the current Unix Timestamp divided by the $keyRegeneration
     * period.
     *
     **/
    public function getTimestamp(): int
    {
        return (int) floor(microtime(true) / $this->keyRegeneration);
    }

    /**
     * Get a list of valid HMAC algorithms.
     */
    protected function getValidAlgorithms(): array
    {
        return [
            Constants::SHA1,
            Constants::SHA256,
            Constants::SHA512,
        ];
    }

    /**
     * Get the OTP window.
     */
    public function getWindow(?int $window = null): int
    {
        return is_null($window) ? $this->window : $window;
    }

    /**
     * Make a window based starting timestamp.
     */
    private function makeStartingTimestamp(?int $window, int $timestamp, ?int $oldTimestamp = null): mixed
    {
        return is_null($oldTimestamp)
            ? $timestamp - $this->getWindow($window)
            : max($timestamp - $this->getWindow($window), $oldTimestamp + 1);
    }

    /**
     * Get/use a starting timestamp for key verification.
     */
    protected function makeTimestamp(int|string|null $timestamp = null): int
    {
        if (is_null($timestamp)) {
            return $this->getTimestamp();
        }

        return (int) $timestamp;
    }

    /**
     * Takes the secret key and the timestamp and returns the one time
     * password.
     *
     * @param  string  $secret  Secret key in binary form.
     * @param  int  $counter  Timestamp as returned by getTimestamp.
     *
     * @throws InvalidCharactersException
     * @throws Exceptions\IncompatibleWithGoogleAuthenticatorException
     * @throws SecretKeyTooShortException
     */
    public function oathTotp(
        #[\SensitiveParameter] string $secret,
        int $counter
    ): string {
        if (strlen($secret) < 8) {
            throw new SecretKeyTooShortException;
        }

        $secret = $this->base32Decode($this->getSecret($secret));

        return str_pad(
            $this->oathTruncate($this->generateHotp($secret, $counter)),
            $this->getOneTimePasswordLength(),
            '0',
            STR_PAD_LEFT
        );
    }

    /**
     * Extracts the OTP from the SHA1 hash.
     *
     * @param  string  $hash
     */
    public function oathTruncate(
        #[\SensitiveParameter] string $hash
    ): string {
        $offset = ord($hash[strlen($hash) - 1]) & 0xF;

        $temp = unpack('N', substr($hash, $offset, 4));

        $temp = $temp[1] & 0x7FFFFFFF;

        return substr(
            (string) $temp,
            -$this->getOneTimePasswordLength()
        );
    }

    /**
     * Remove invalid chars from a base 32 string.
     */
    public function removeInvalidChars(string $string): ?string
    {
        return preg_replace(
            '/[^'.Constants::VALID_FOR_B32.']/',
            '',
            $string
        );
    }

    /**
     * Setter for the enforce Google Authenticator compatibility property.
     *
     *
     * @return $this
     */
    public function setEnforceGoogleAuthenticatorCompatibility(
        mixed $enforceGoogleAuthenticatorCompatibility
    ): static {
        $this->enforceGoogleAuthenticatorCompatibility = $enforceGoogleAuthenticatorCompatibility;

        return $this;
    }

    /**
     * Set the HMAC hashing algorithm.
     *
     *
     * @return Google2FA
     *
     * @throws InvalidAlgorithmException
     */
    public function setAlgorithm(mixed $algorithm): static
    {
        // Default to SHA1 HMAC algorithm
        if (! in_array($algorithm, $this->getValidAlgorithms())) {
            throw new InvalidAlgorithmException;
        }

        $this->algorithm = $algorithm;

        return $this;
    }

    /**
     * Set key regeneration.
     */
    public function setKeyRegeneration(mixed $keyRegeneration): void
    {
        $this->keyRegeneration = $keyRegeneration;
    }

    /**
     * Set OTP length.
     */
    public function setOneTimePasswordLength(mixed $oneTimePasswordLength): void
    {
        $this->oneTimePasswordLength = $oneTimePasswordLength;
    }

    /**
     * Set secret.
     *
     * @param  mixed  $secret
     */
    public function setSecret(
        #[\SensitiveParameter] mixed $secret
    ): void {
        $this->secret = $secret;
    }

    /**
     * Set the OTP window.
     */
    public function setWindow(mixed $window): void
    {
        $this->window = $window;
    }

    /**
     * Verifies a user inputted key against the current timestamp. Checks $window
     * keys either side of the timestamp.
     *
     * @param  string  $key  User specified key
     * @param  string  $secret
     *
     * @throws IncompatibleWithGoogleAuthenticatorException
     * @throws InvalidCharactersException
     * @throws SecretKeyTooShortException
     */
    public function verify(
        #[\SensitiveParameter] string $key,
        #[\SensitiveParameter] string $secret,
        ?int $window = null,
        ?int $timestamp = null,
        ?int $oldTimestamp = null
    ): bool|int {
        return $this->verifyKey(
            $secret,
            $key,
            $window,
            $timestamp,
            $oldTimestamp
        );
    }

    /**
     * Verifies a user inputted key against the current timestamp. Checks $window
     * keys either side of the timestamp.
     *
     * @param  string  $secret
     * @param  string  $key  User specified key
     *
     * @throws IncompatibleWithGoogleAuthenticatorException
     * @throws InvalidCharactersException
     * @throws SecretKeyTooShortException
     */
    public function verifyKey(
        #[\SensitiveParameter] string $secret,
        #[\SensitiveParameter] string $key,
        ?int $window = null,
        ?int $timestamp = null,
        ?int $oldTimestamp = null
    ): bool|int {
        $timestamp = $this->makeTimestamp($timestamp);

        return $this->findValidOTP(
            $secret,
            $key,
            $window,
            $this->makeStartingTimestamp($window, $timestamp, $oldTimestamp),
            $timestamp,
            $oldTimestamp
        );
    }

    /**
     * Verifies a user inputted key against the current timestamp. Checks $window
     * keys either side of the timestamp, but ensures that the given key is newer than
     * the given oldTimestamp. Useful if you need to ensure that a single key cannot
     * be used twice.
     *
     * @param  string  $secret
     * @param  string  $key  User specified key
     * @param  int|null  $oldTimestamp  The timestamp from the last verified key
     *
     * @throws IncompatibleWithGoogleAuthenticatorException
     * @throws InvalidCharactersException
     * @throws SecretKeyTooShortException
     */
    public function verifyKeyNewer(
        #[\SensitiveParameter] string $secret,
        #[\SensitiveParameter] string $key,
        ?int $oldTimestamp,
        ?int $window = null,
        ?int $timestamp = null
    ): bool|int {
        return $this->verifyKey(
            $secret,
            $key,
            $window,
            $timestamp,
            $oldTimestamp
        );
    }
}
