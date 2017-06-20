<?php

namespace PragmaRX\Google2FA\Support;

use ParagonIE\ConstantTime\Base32 as ParagonieBase32;

trait Base32
{
    /**
     * Generate a digit secret key in base32 format.
     *
     * @param int $length
     *
     * @return string
     */
    public function generateBase32RandomKey($length = 16, $prefix = '')
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

        return ParagonieBase32::decodeUpper($b32);
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
        $encoded = ParagonieBase32::encodeUpper($string);

        return str_replace('=', '', $encoded);
    }

    /**
     * Get a random number.
     *
     * @param $from
     * @param $to
     *
     * @return int
     */
    protected function getRandomNumber($from = 0, $to = 31)
    {
        return random_int($from, $to);
    }
}
