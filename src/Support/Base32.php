<?php

namespace PragmaRX\Google2FA\Support;

use ParagonIE\ConstantTime\Base32 as ParagonieBase32;
use PragmaRX\Google2FA\Exceptions\IncompatibleWithGoogleAuthenticatorException;
use PragmaRX\Google2FA\Exceptions\InvalidCharactersException;
use PragmaRX\Google2FA\Exceptions\SecretKeyTooShortException;

trait Base32
{
    /**
     * Enforce Google Authenticator compatibility.
     */
    protected bool $enforceGoogleAuthenticatorCompatibility = true;

    /**
     * Calculate char count bits.
     */
    protected function charCountBits(
        #[\SensitiveParameter]
        string $b32
    ): int {
        return strlen($b32) * 8;
    }

    /**
     * Generate a digit secret key in base32 format.
     *
     * @throws \Exception
     * @throws \PragmaRX\Google2FA\Exceptions\InvalidCharactersException
     * @throws \PragmaRX\Google2FA\Exceptions\SecretKeyTooShortException
     * @throws \PragmaRX\Google2FA\Exceptions\IncompatibleWithGoogleAuthenticatorException
     */
    public function generateBase32RandomKey(
        int $length = 16,
        #[\SensitiveParameter]
        string $prefix = ''
    ): string {
        $secret = $prefix ? $this->toBase32($prefix) : '';

        $secret = $this->strPadBase32($secret, $length);

        $this->validateSecret($secret);

        return $secret;
    }

    /**
     * Decodes a base32 string into a binary string.
     *
     * @throws \PragmaRX\Google2FA\Exceptions\InvalidCharactersException
     * @throws \PragmaRX\Google2FA\Exceptions\SecretKeyTooShortException
     * @throws \PragmaRX\Google2FA\Exceptions\IncompatibleWithGoogleAuthenticatorException
     */
    public function base32Decode(
        #[\SensitiveParameter]
        string $b32
    ): string {
        $b32 = strtoupper($b32);

        $this->validateSecret($b32);

        return ParagonieBase32::decodeUpper($b32);
    }

    /**
     * Check if the string length is power of two.
     */
    protected function isCharCountNotAPowerOfTwo(
        #[\SensitiveParameter]
        string $b32
    ): bool {
        return (strlen($b32) & (strlen($b32) - 1)) !== 0;
    }

    /**
     * Pad string with random base 32 chars.
     *
     * @throws \Exception
     */
    private function strPadBase32(
        #[\SensitiveParameter]
        string $string,
        int $length
    ): string {
        for ($i = 0; $i < $length; $i++) {
            $string .= substr(
                Constants::VALID_FOR_B32_SCRAMBLED,
                $this->getRandomNumber(),
                1
            );
        }

        return $string;
    }

    /**
     * Encode a string to Base32.
     */
    public function toBase32(
        #[\SensitiveParameter]
        string $string
    ): string {
        $encoded = ParagonieBase32::encodeUpper($string);

        return str_replace('=', '', $encoded);
    }

    /**
     * Get a random number.
     *
     * @throws \Exception
     */
    protected function getRandomNumber(int $from = 0, int $to = 31): int
    {
        return random_int($from, $to);
    }

    /**
     * Validate the secret.
     *
     * @throws \PragmaRX\Google2FA\Exceptions\InvalidCharactersException
     * @throws \PragmaRX\Google2FA\Exceptions\SecretKeyTooShortException
     * @throws \PragmaRX\Google2FA\Exceptions\IncompatibleWithGoogleAuthenticatorException
     */
    protected function validateSecret(
        #[\SensitiveParameter]
        string $b32
    ): void {
        $this->checkForValidCharacters($b32);

        $this->checkGoogleAuthenticatorCompatibility($b32);

        $this->checkIsBigEnough($b32);
    }

    /**
     * Check if the secret key is compatible with Google Authenticator.
     *
     * @throws IncompatibleWithGoogleAuthenticatorException
     */
    protected function checkGoogleAuthenticatorCompatibility(
        #[\SensitiveParameter]
        string $b32
    ): void {
        if (
            $this->enforceGoogleAuthenticatorCompatibility &&
            $this->isCharCountNotAPowerOfTwo($b32) // Google Authenticator requires it to be a power of 2 base32 length string
        ) {
            throw new IncompatibleWithGoogleAuthenticatorException();
        }
    }

    /**
     * Check if all secret key characters are valid.
     *
     * @throws \PragmaRX\Google2FA\Exceptions\InvalidCharactersException
     */
    protected function checkForValidCharacters(
        #[\SensitiveParameter]
        string $b32
    ): void {
        if (
            preg_replace('/[^'.Constants::VALID_FOR_B32.']/', '', $b32) !==
            $b32
        ) {
            throw new InvalidCharactersException();
        }
    }

    /**
     * Check if secret key length is big enough.
     *
     * @throws \PragmaRX\Google2FA\Exceptions\SecretKeyTooShortException
     */
    protected function checkIsBigEnough(
        #[\SensitiveParameter]
        string $b32
    ): void {
        // Minimum = 128 bits
        // Recommended = 160 bits
        // Compatible with Google Authenticator = 256 bits

        if (
            $this->charCountBits($b32) < 128
        ) {
            throw new SecretKeyTooShortException();
        }
    }
}
