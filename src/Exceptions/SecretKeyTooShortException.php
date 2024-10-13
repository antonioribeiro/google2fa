<?php
declare(strict_types = 1);

namespace PragmaRX\Google2FA\Exceptions;

use PragmaRX\Google2FA\Exceptions\Contracts\Google2FA as Google2FAExceptionContract;
use PragmaRX\Google2FA\Exceptions\Contracts\SecretKeyTooShort as SecretKeyTooShortExceptionContract;
use Throwable;

class SecretKeyTooShortException extends Google2FAException implements Google2FAExceptionContract, SecretKeyTooShortExceptionContract
{
    public function __construct(int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct('Secret key is too short. Must be at least 16 base32 characters.', $code, $previous);
    }
}
