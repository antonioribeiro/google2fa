<?php

namespace PragmaRX\Google2FA\Exceptions;

use Exception;

class IncompatibleWithGoogleAuthenticatorException extends Exception
{
    protected $message = 'Invalid characters in the base32 string.';
}
