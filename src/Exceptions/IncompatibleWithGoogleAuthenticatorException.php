<?php

namespace PragmaRX\Google2FA\Exceptions;

class IncompatibleWithGoogleAuthenticatorException extends Google2FAException
{
    protected $message = 'This secret key is not compatible with Google Authenticator.';
}
