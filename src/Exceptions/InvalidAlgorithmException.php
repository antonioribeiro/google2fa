<?php

declare(strict_types=1);

namespace PragmaRX\Google2FA\Exceptions;

use Throwable;
use PragmaRX\Google2FA\Exceptions\Contracts\Google2FA as Google2FAExceptionContract;
use PragmaRX\Google2FA\Exceptions\Contracts\InvalidAlgorithm as InvalidAlgorithmExceptionContract;

class InvalidAlgorithmException extends Google2FAException implements
    Google2FAExceptionContract,
    InvalidAlgorithmExceptionContract
{
    public function __construct(int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct('Invalid HMAC algorithm.', $code, $previous);
    }
}
