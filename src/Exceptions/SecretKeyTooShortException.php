<?php

namespace PragmaRX\Google2FA\Exceptions;

class SecretKeyTooShortException extends Google2FAException
{
    protected $message = 'Secret key is too short. Must be at least 16 base32 characters';
}
