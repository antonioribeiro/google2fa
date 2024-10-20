<?php

declare(strict_types=1);

namespace PragmaRX\Google2FA\Support;

class Constants
{
    /**
     * Characters valid for Base 32.
     */
    public const VALID_FOR_B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /**
     * Characters valid for Base 32, scrambled.
     */
    public const VALID_FOR_B32_SCRAMBLED = '234567QWERTYUIOPASDFGHJKLZXCVBNM';

    /**
     * SHA1 algorithm.
     */
    public const SHA1 = 'sha1';

    /**
     * SHA256 algorithm.
     */
    public const SHA256 = 'sha256';

    /**
     * SHA512 algorithm.
     */
    public const SHA512 = 'sha512';
}
