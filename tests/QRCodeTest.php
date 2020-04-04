<?php

namespace PragmaRX\Google2FA\Tests;

use PHPUnit\Framework\TestCase;
use PragmaRX\Google2FA\Google2FA;
use PragmaRX\Google2FA\Support\Constants as Google2FAConstants;

class QRCodeTest extends TestCase
{
    /**
     * @var \PragmaRX\Google2FA\Google2FA
     */
    public $google2fa;

    public function setUp(): void
    {
        $this->google2fa = new Google2FA();
    }

    public function testCanGetQRCode()
    {
        $secretKey = $this->google2fa->generateSecretKey();

        $this->assertEquals(
            $this->google2fa->getQRCodeUrl('company', 'holder', $secretKey),
            "otpauth://totp/company:holder?secret={$secretKey}&issuer=company&algorithm=SHA1&digits=6&period=30"
        );
    }

    public function testCanGetQRCodeUrl()
    {
        $secretKey = $this->google2fa->generateSecretKey();

        $this->assertEquals(
            $this->google2fa->generateGoogleQRCodeUrl('company.com', 'page', ['param1' => 'value1']),
            "otpauth://totp/company:holder?secret={$secretKey}&issuer=company&algorithm=SHA1&digits=6&period=30"
        );
    }

}
