<?php

namespace spec\PragmaRX\Google2FA;

use PragmaRX\Google2FA\Google2FA;
use PragmaRX\Google2FA\Support\Constants;

class Google2FATest extends \PHPUnit_Framework_TestCase
{
    const SECRET = 'ADUMJO5634NPDEKW';

    const SHORT_SECRET = 'ADUMJO5';

    const INVALID_SECRET = 'DUMJO5634NPDEKX@';

    const WRONG_SECRET = 'ADUMJO5634NPDEKX';

    const URL = 'https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth%3A%2F%2Ftotp%2FPragmaRX%3Aacr%252Bpragmarx%2540antoniocarlosribeiro.com%3Fsecret%3DADUMJO5634NPDEKW%26issuer%3DPragmaRX';

    const QRCODE = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAMgAAADICAIAAAAiOjnJAAAFjklEQVR4nO3dwY6dOhBF0ZdW/v+TW28WMbhWV1Fn25DsNYzAkOSIW7JN8ev7+/s/Ke3r9A3o72SwhDBYQhgsIQyWEAZLCIMlhMESwmAJYbCEMFhCGCwhDJYQBksIgyWEwRLCYAnx+95pX1/5RE72sq7upzLm9dzJ8ZN7qFyrMuZz/l98YglhsIQwWELcrLGuiBqiWyusah269uoeU3EdZ3Jd4v+lMcLwfOkjgyWEwRIiUGNdVX6bK7/9q5opVUt1a7vuPVTqpMp1u8dMzs2+E+8TSwiDJYTBEiJcY6VUappU7dIdZzK/1a2Tun/f5/CJJYTBEsJgCfHQGitVT3Trs8pcVGp9s4vY78XxiSWEwRLCYAkRrrFSv/eT+ZvJuttkXio1p5Waw7vaX4f5xBLCYAlhsIQI1Fj0/E33Hrp7uVJ1zM77IfbaZ53PhP5KBksIgyXEzRqLnheZzPdUxunukUrNG+38dzvLJ5YQBksIgyXEgf5Yk/pmsme88udEP63KdbtOzY3V+cQSwmAJYbCECPfHIvpznuqrmeqVMJnTmvS56MrWWz6xhDBYQhgsIX6FuyIN9gntn2vJ3ltlnJXJfBgxl+Y8lh7KYAlhsIS4WWN1a5EVYn/3zj3jp+4z1XOV+xaQTywhDJYQBkuIcI21Mvnt795D6rs3k2Mqx+/8vmFq/MadbLiG/kEGSwiDJURgrXBnXTK5t5VT9VzFznm4ynXrfGIJYbCEMFhCHHivcDUO/Y4e0V+0gu4Zkfo39HuFegGDJYTBEiK85/2K6KW+Qvde33nd7nriE9ZtP4x24xzpRwZLCIMlxKa1wtXxFTvX4ybo2rE75s412Q8jB8eS/jBYQhgsIcJrhZW5EGLdrXsPK8QcUqoP1hPWZxtXgcbVP85gCWGwhAh/E3qFWAtL9XyvSNVAqZpm8u2gK+ex9DIGSwiDJUR4rfDq7e/craTWBIn9WKmeFKtr1fnEEsJgCWGwhAD7YxH7srvo3g1vGWfP+uCVTywhDJYQBksIcM/7zrWznf1FT/VKSL0LeeV+LL2MwRLCYAmx6Vs6qe/A0HvD6bW2U+9U7q+DfWIJYbCEMFhCBGqsnX2eiL1QlXFWx3Tvc4XucVUZx/1YegGDJYTBEgJ8r7Dye5/6RnL3XGJ/0qk+8t176J57j08sIQyWEAZLiPA8VuUYYq6L3seder+PQPQd9XuFeiiDJYTBEiIwj0V/f6Z7D6n9Ut37mczD7ezPvqdm9YklhMESwmAJEf5eIVHHpPpgPbmHFnHdSf3kPJYeymAJYbCEONAf69R7dk/o3bAap4J4p9LeDXoZgyWEwRICrLGuTn3jZWfPz8mYk3vY2S++zieWEAZLCIMlxIHeDal1w66d7/0RfSi6x6Tu5x6fWEIYLCEMlhDh3g2r3+nUXEuqbqNru+5eK7qv2Ir9sfQyBksIgyXEg/pjXaX2gxM9Rel3D7vndu3pK+ETSwiDJYTBEiL8XmHKpIZY2VmjPO27h/T3iz6McOMc6UcGSwiDJcTNeSy6BuoeQ+zBJ95D7N5D184+Wz+MHBxL+sNgCWGwhAisFRLv/VW+gVM5frIvavXn3f1hq3Em654rk7XLLJ9YQhgsIQyWEOH9WDt7JXT316fuJ7XulvomY2pO0d4NegGDJYTBEgLc807o1jGptT9iDTE195Za93StUC9gsIQwWEK8oMaavHM3qVdWxxPf5CHW+LrroZP7+XCV4fnSRwZLCIMlxKb+WCnEN3lW625P6MtVMVmLvMruwfeJJYTBEsJgCRGosYh3DFd29lufjEN892Zy3e68nfNYeiiDJYTBEuKh/bH0dj6xhDBYQhgsIQyWEAZLCIMlhMESwmAJYbCEMFhCGCwhDJYQBksIgyWEwRLCYAlhsIT4HybO2zx85W0PAAAAAElFTkSuQmCC';

    public function setUp()
    {
        $this->google2fa = new Google2FA();
    }

    public function test_is_initializable()
    {
        $this->isInstanceOf($this->google2fa, Google2FA::class);
    }

    public function test_generates_a_valid_secret_key()
    {
        $this->assertEquals(16, strlen($this->google2fa->generateSecretKey()));

        $this->assertEquals(32, strlen($this->google2fa->generateSecretKey(32)));

        $this->assertStringStartsWith('MFXHI', $this->google2fa->generateSecretKey(59, 'ant'));

        $this->assertStringStartsWith('MFXHI', $this->google2fa->generateSecretKey(59, 'ant'));

        $this->assertEquals($key = $this->google2fa->generateSecretKey(), preg_replace('/[^'.Constants::VALID_FOR_B32.']/', '', $key));
    }

    /**
     * @expectedException  \PragmaRX\Google2FA\Exceptions\IncompatibleWithGoogleAuthenticatorException
     */
    public function test_generates_a_secret_keys_compatible_with_google_authenticator_or_not()
    {
        $this->google2fa->setEnforceGoogleAuthenticatorCompatibility(true)->generateSecretKey(17);

        $this->assertEquals(17, strlen($this->google2fa->setEnforceGoogleAuthenticatorCompatibility(false)->generateSecretKey(17)));
    }

    public function test_converts_invalid_chars_to_base32()
    {
        $converted = $this->google2fa->generateBase32RandomKey(16, '1234'.chr(250).chr(251).chr(252).chr(253).chr(254).chr(255));

        $valid = preg_replace('/[^'.Constants::VALID_FOR_B32.']/', '', $converted);

        $this->assertEquals($converted, $valid);
    }

    public function test_gets_valid_timestamps()
    {
        $ts = $this->google2fa->getTimestamp();

        $this->assertLessThanOrEqual(PHP_INT_MAX, $ts);

        $this->assertGreaterThanOrEqual(~PHP_INT_MAX, $ts);
    }

    public function test_decodes_base32_strings()
    {
        $result = chr(0)
            .chr(232)
            .chr(196)
            .chr(187)
            .chr(190)
            .chr(223)
            .chr(26)
            .chr(241)
            .chr(145)
            .chr(86);

        $this->assertEquals($result, $this->google2fa->base32Decode(static::SECRET));
    }

    public function test_creates_a_one_time_password()
    {
        $this->assertEquals(6, strlen($this->google2fa->getCurrentOtp(static::SECRET)));
    }

    public function test_verifies_keys()
    {
        // $ts 26213400 with KEY_REGENERATION 30 seconds is
        // timestamp 786402000, which is 1994-12-02 21:00:00 UTC

        $this->assertTrue($this->google2fa->verifyKey(static::SECRET, '558854', 2, 26213400));  // 26213398
        $this->assertTrue($this->google2fa->verifyKey(static::SECRET, '981084', 2, 26213400));  // 26213399
        $this->assertTrue($this->google2fa->verifyKey(static::SECRET, '512396', 2, 26213400));  // 26213400
        $this->assertTrue($this->google2fa->verifyKey(static::SECRET, '410272', 2, 26213400));  // 26213401
        $this->assertTrue($this->google2fa->verifyKey(static::SECRET, '239815', 2, 26213400));  // 26213402

        $this->assertFalse($this->google2fa->verifyKey(static::SECRET, '313366', 2, 26213400)); // 26213403
        $this->assertFalse($this->google2fa->verifyKey(static::SECRET, '093183', 2, 26213400)); // 26213397
    }

    public function test_verifies_keys_newer()
    {
        $this->assertFalse($this->google2fa->verifyKeyNewer(static::SECRET, '512396', 26213401, 2, 26213400));
        $this->assertFalse($this->google2fa->verifyKeyNewer(static::SECRET, '410272', 26213401, 2, 26213400));
        $this->assertEquals(26213402, $this->google2fa->verifyKeyNewer(static::SECRET, '239815', 26213401, 2, 26213400));
        $this->assertFalse($this->google2fa->verifyKeyNewer(static::SECRET, '313366', 26213401, 2, 26213400));

        $this->assertEquals(26213400, $this->google2fa->verifyKeyNewer(static::SECRET, '512396', null, 2, 26213400));
        $this->assertEquals(26213401, $this->google2fa->verifyKeyNewer(static::SECRET, '410272', null, 2, 26213400));
        $this->assertEquals(26213402, $this->google2fa->verifyKeyNewer(static::SECRET, '239815', null, 2, 26213400));
        $this->assertFalse($this->google2fa->verifyKeyNewer(static::SECRET, '313366', null, 2, 26213400));
    }

    public function test_removes_invalid_chars_from_secret()
    {
        $this->assertEquals(static::SECRET, $this->google2fa->removeInvalidChars(static::SECRET.'!1-@@@'));
    }

    public function test_creates_a_qr_code()
    {
        $this->assertEquals(static::URL, $this->google2fa->getQRCodeGoogleUrl('PragmaRX', 'acr+pragmarx@antoniocarlosribeiro.com', static::SECRET));
    }

    public function test_converts_to_base32()
    {
        $this->assertEquals('KBZGCZ3NMFJFQ', $this->google2fa->toBase32('PragmaRX'));
    }

    public function test_sets_the_window()
    {
        $this->google2fa->setWindow(6);

        $this->assertEquals(6, $this->google2fa->getWindow());

        $this->assertEquals(1, $this->google2fa->getWindow(1));

        $this->google2fa->setWindow(0);

        $this->assertFalse($this->google2fa->verifyKey(static::SECRET, '558854', null, 26213400));

        $this->google2fa->setWindow(2);

        $this->assertTrue($this->google2fa->verifyKey(static::SECRET, '558854', null, 26213400));
        $this->assertTrue($this->google2fa->verifyKey(static::SECRET, '558854', null, 26213399));
        $this->assertTrue($this->google2fa->verifyKey(static::SECRET, '558854', null, 26213398));
        $this->assertTrue($this->google2fa->verifyKey(static::SECRET, '558854', null, 26213396));
        $this->assertFalse($this->google2fa->verifyKey(static::SECRET, '558854', null, 26213395));
    }

    public function test_sets_the_secret()
    {
        $this->assertFalse($this->google2fa->verify('558854', static::WRONG_SECRET));

        $this->google2fa->setWindow(2);

        $this->assertTrue($this->google2fa->verify('558854', static::SECRET, null, 26213400));

        $this->google2fa->setSecret(static::SECRET);

        $this->assertTrue($this->google2fa->verify('558854', null, null, 26213400));
    }

    public function test_gets_key_regeneration()
    {
        $this->google2fa->setKeyRegeneration(11);

        $this->assertEquals(11, $this->google2fa->getKeyRegeneration());
    }

    public function test_gets_otp_length()
    {
        $this->google2fa->setOneTimePasswordLength(7);

        $this->assertEquals(7, $this->google2fa->getOneTimePasswordLength());
    }

    public function test_generates_passwords_in_many_different_sizes()
    {
        $this->google2fa->setWindow(2);

        $this->google2fa->setOneTimePasswordLength(6);

        $this->assertTrue($this->google2fa->verifyKey(static::SECRET, '558854', null, 26213400));

        $this->google2fa->setOneTimePasswordLength(7);

        $this->assertTrue($this->google2fa->verifyKey(static::SECRET, '8981084', null, 26213400));
    }

    /**
     * @expectedException  \PragmaRX\Google2FA\Exceptions\SecretKeyTooShortException
     */
    public function test_short_secret_key()
    {
        $this->google2fa->setEnforceGoogleAuthenticatorCompatibility(false);

        $this->google2fa->verifyKey(static::SHORT_SECRET, '558854', null, 26213400);
    }

    /**
     * @expectedException  \PragmaRX\Google2FA\Exceptions\InvalidCharactersException
     */
    public function test_validate_key()
    {
        $this->assertTrue(is_numeric($this->google2fa->getCurrentOtp(static::SECRET)));

        $this->google2fa->setEnforceGoogleAuthenticatorCompatibility(false);

        $this->google2fa->getCurrentOtp(static::INVALID_SECRET);
    }

    public function test_qrcode_inline()
    {
        $this->assertEquals(static::QRCODE, $this->google2fa->getQRCodeInline('PragmaRX', 'acr+pragmarx@antoniocarlosribeiro.com', static::SECRET));
    }
}
