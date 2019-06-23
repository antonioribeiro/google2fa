<?php

namespace PragmaRX\Google2FA\Exceptions;

use Exception;

class InvalidCharactersException extends Exception implements Google2FAExceptionInterface
{
    protected $message = 'Invalid characters in the base32 string.';
}
