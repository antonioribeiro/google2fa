<?php

namespace PragmaRX\Google2FA\Exceptions;

class InvalidCharactersException extends Google2FAException
{
    protected $message = 'Invalid characters in the base32 string.';
}
