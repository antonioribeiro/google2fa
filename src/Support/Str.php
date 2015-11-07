<?php

namespace PragmaRX\Google2FA\Support;

class Str
{
    /**
     * Compares two strings using a constant-time algorithm.
     *
     * Note: This method will leak length information.
     *
     * Note: Extracted from Illuminate\Support\Str.
     *
     * Note: Adapted from Symfony\Component\Security\Core\Util\StringUtils.
     *
     * @param  string  $knownString
     * @param  string  $userInput
     * @return bool
     */
    public static function equals($knownString, $userInput)
    {
        if (! is_string($knownString)) {
            $knownString = (string) $knownString;
        }

        if (! is_string($userInput)) {
            $userInput = (string) $userInput;
        }

        if (function_exists('hash_equals')) {
            return hash_equals($knownString, $userInput);
        }

        $mb = function_exists('mb_string');

        $knownLength = $mb ? mb_strlen($knownString, '8bit') : strlen($knownString);

        if (($mb ? mb_strlen($userInput, '8bit') : strlen($userInput)) !== $knownLength) {
            return false;
        }

        $result = 0;

        for ($i = 0; $i < $knownLength; ++$i) {
            $result |= (ord($knownString[$i]) ^ ord($userInput[$i]));
        }

        return 0 === $result;
    }
}
