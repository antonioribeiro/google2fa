<?php

namespace PragmaRX\Google2FA\Support;

trait QRCode
{
    /**
     * Creates a QR code url.
     */
    public function getQRCodeUrl(
        string $company,
        string $holder,
        #[\SensitiveParameter]
        string $secret
    ): string  {
        return 'otpauth://totp/'.
            rawurlencode($company).
            ':'.
            rawurlencode($holder).
            '?secret='.
            $secret.
            '&issuer='.
            rawurlencode($company).
            '&algorithm='.
            rawurlencode(strtoupper($this->getAlgorithm())).
            '&digits='.
            rawurlencode(strtoupper((string) $this->getOneTimePasswordLength())).
            '&period='.
            rawurlencode(strtoupper((string) $this->getKeyRegeneration())).
            '';
    }
}
