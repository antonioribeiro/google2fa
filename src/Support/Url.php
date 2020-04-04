<?php

namespace PragmaRX\Google2FA\Support;

class Url
{
    /**
     * Generate a Google QRCode Url
     *
     * @param $domain
     * @param $page
     * @param $queryParameters
     * @param $qrCodeUrl
     *
     * @return string
     */
    public static function generateGoogleQRCodeUrl(
        $domain,
        $page,
        $queryParameters,
        $qrCodeUrl
    ) {
        return $domain.
            rawurlencode($page).
            '?'.
            $queryParameters.
            urlencode($qrCodeUrl);
    }
}
