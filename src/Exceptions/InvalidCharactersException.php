<?php

namespace PragmaRX\Google2FA\Exceptions;

use PragmaRX\Google2FA\Exceptions\Contracts\Google2FA as Google2FAExceptionContract;
use PragmaRX\Google2FA\Exceptions\Contracts\InvalidCharacters as InvalidCharactersExceptionContract;
use Throwable;

class InvalidCharactersException extends Google2FAException implements Google2FAExceptionContract, InvalidCharactersExceptionContract
{
    public function __construct(int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct('Invalid characters in the base32 string.', $code, $previous);
    }
}
