<?php

namespace PragmaRX\Google2FA\Exceptions;

use Exception;

class InvalidCharactersException extends Exception
{
    protected $message = 'This secret key is not compatible with Google Authenticator.';
}
