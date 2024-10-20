<?php

declare(strict_types=1);

namespace PragmaRX\Google2FA\Exceptions;

use Throwable;
use PragmaRX\Google2FA\Exceptions\Contracts\Google2FA as Google2FAExceptionContract;
use PragmaRX\Google2FA\Exceptions\Contracts\InvalidHash as InvalidHashExceptionContract;

class InvalidHashException extends Google2FAException implements
    Google2FAExceptionContract,
    InvalidHashExceptionContract
{
    public function __construct(string $message = '', int $code = 0, ?Throwable $previous = null)
    {
        $error = 'Invalid hash to unpack';
        if ($message !== '') {
            $error .= ': ' . $message;
        }
        parent::__construct($error, $code, $previous);
    }
}
