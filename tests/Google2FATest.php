<?php

namespace PragmaRX\Google2FA\Tests;

use PHPUnit\Framework\TestCase;
use PragmaRX\Google2FA\Google2FA;
use PragmaRX\Google2FA\Support\Constants as Google2FAConstants;

if (!trait_exists('PragmaRX\Google2FA\Tests\TestCaseTrait')) {
    require __DIR__ . '/autoload.php';
}

class Google2FATest extends TestCase
{
    use TestCaseTrait;

    /** @var Google2FA */
    protected $google2fa;

    public function setUpCompat()
    {
        $this->google2fa = new Google2FA();
    }

    public function testIsInitializable()
    {
        $this->assertInstanceOf(
            'PragmaRX\Google2FA\Google2FA',
            $this->google2fa
        );
    }

    public function testGeneratesAValidSecretKey()
    {
        $this->assertEquals(16, strlen($this->google2fa->generateSecretKey()));

        $this->assertEquals(
            32,
            strlen($this->google2fa->generateSecretKey(32))
        );

        $this->assertStringStartsWith(
            'MFXHI',
            $this->google2fa->generateSecretKey(59, 'ant')
        );

        $this->assertStringStartsWith(
            'MFXHI',
            $this->google2fa->generateSecretKey(59, 'ant')
        );

        $this->assertEquals(
            $key = $this->google2fa->generateSecretKey(),
            preg_replace(
                '/[^' . Google2FAConstants::VALID_FOR_B32 . ']/',
                '',
                $key
            )
        );
    }

    public function testGeneratesASecretKeysCompatibleWithGoogleAuthenticator()
    {
        $this->assertEquals($size =  16, strlen($this->google2fa->setEnforceGoogleAuthenticatorCompatibility(true)->generateSecretKey($size)));  /// minimum = 128 bits
        $this->assertEquals($size =  20, strlen($this->google2fa->setEnforceGoogleAuthenticatorCompatibility(false)->generateSecretKey($size))); /// recommended = 160 bits - not compatible
        $this->assertEquals($size =  32, strlen($this->google2fa->setEnforceGoogleAuthenticatorCompatibility(true)->generateSecretKey($size)));  /// recommended = 256 bits - compatible
        $this->assertEquals($size =  64, strlen($this->google2fa->setEnforceGoogleAuthenticatorCompatibility(true)->generateSecretKey($size)));
        $this->assertEquals($size = 128, strlen($this->google2fa->setEnforceGoogleAuthenticatorCompatibility(true)->generateSecretKey($size)));
    }

    /**
     * @dataProvider generatesASecretKeysGenerationSizeProvider
     * anything below 128 bits are NOT allowed
     * @expectedException  \PragmaRX\Google2FA\Exceptions\SecretKeyTooShortException
     */
    public function testGeneratesASecretKeysGenerationSize($size)
    {
        // 128 bits are allowed
        $this->assertEquals(16, strlen($this->google2fa->generateSecretKey(16)));  /// minimum = 128 bits

        // exception
        $this->assertEquals($size, strlen($this->google2fa->generateSecretKey($size)));  /// minimum = 128 bits
    }

    public function generatesASecretKeysGenerationSizeProvider()
    {
        return array(
            array(2),
            array(4),
            array(8),
        );
    }

    /**
     * @param int $size
     * @dataProvider generatesASecretKeysNotCompatibleWithGoogleAuthenticatorProvider
     * @expectedException \PragmaRX\Google2FA\Exceptions\IncompatibleWithGoogleAuthenticatorException
     */
    public function testGeneratesASecretKeysNotCompatibleWithGoogleAuthenticator($size)
    {
        $this->assertEquals($size, strlen($this->google2fa->setEnforceGoogleAuthenticatorCompatibility(true)->generateSecretKey($size)));
    }

    public function generatesASecretKeysNotCompatibleWithGoogleAuthenticatorProvider()
    {
        return array(
            array(15),
            array(17),
            array(21),
        );
    }

    public function testConvertsInvalidCharsToBase32()
    {
        $converted = $this->google2fa->generateBase32RandomKey(
            16,
            '1234' .
            chr(250) .
            chr(251) .
            chr(252) .
            chr(253) .
            chr(254) .
            chr(255)
        );

        $valid = preg_replace(
            '/[^' . Google2FAConstants::VALID_FOR_B32 . ']/',
            '',
            $converted
        );

        $this->assertEquals($converted, $valid);
    }

    public function testGetsValidTimestamps()
    {
        $ts = $this->google2fa->getTimestamp();

        $this->assertLessThanOrEqual(PHP_INT_MAX, $ts);

        $this->assertGreaterThanOrEqual(~PHP_INT_MAX, $ts);
    }

    public function testDecodesBase32Strings()
    {
        $result =
            chr(0) .
            chr(232) .
            chr(196) .
            chr(187) .
            chr(190) .
            chr(223) .
            chr(26) .
            chr(241) .
            chr(145) .
            chr(86);

        $this->assertEquals(
            $result,
            $this->google2fa->base32Decode(Constants::SECRET)
        );
    }

    public function testCreatesAOneTimePassword()
    {
        $this->assertEquals(
            6,
            strlen($this->google2fa->getCurrentOtp(Constants::SECRET))
        );
    }

    public function testVerifiesKeys()
    {
        // $ts 26213400 with KEY_REGENERATION 30 seconds is
        // timestamp 786402000, which is 1994-12-02 21:00:00 UTC

        $this->assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '558854',
                2,
                26213400
            )
        ); // 26213398
        $this->assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '981084',
                2,
                26213400
            )
        ); // 26213399
        $this->assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '512396',
                2,
                26213400
            )
        ); // 26213400
        $this->assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '410272',
                2,
                26213400
            )
        ); // 26213401
        $this->assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '239815',
                2,
                26213400
            )
        ); // 26213402

        $this->assertFalse(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '313366',
                2,
                26213400
            )
        ); // 26213403
        $this->assertFalse(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '093183',
                2,
                26213400
            )
        ); // 26213397
    }

    public function testVerifiesKeysNewer()
    {
        $this->assertFalse(
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '512396',
                26213401,
                2,
                26213400
            )
        ); // 26213400
        $this->assertFalse(
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '410272',
                26213401,
                2,
                26213400
            )
        ); // 26213401
        $this->assertEquals(
            26213402,
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '239815',
                26213401,
                2,
                26213400
            )
        ); // 26213402
        $this->assertFalse(
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '313366',
                26213401,
                2,
                26213400
            )
        ); // 26213403

        $this->assertEquals(
            26213400,
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '512396',
                null,
                2,
                26213400
            )
        ); // 26213400
        $this->assertEquals(
            26213401,
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '410272',
                null,
                2,
                26213400
            )
        ); // 26213401
        $this->assertEquals(
            26213402,
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '239815',
                null,
                2,
                26213400
            )
        ); // 26213402
        $this->assertFalse(
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '313366',
                null,
                2,
                26213400
            )
        ); // 26213403
    }

    public function testVerifiesSha256Keys()
    {
        // $ts 26213400 with KEY_REGENERATION 30 seconds is
        // timestamp 786402000, which is 1994-12-02 21:00:00 UTC

        $this->google2fa->setAlgorithm(Google2FAConstants::SHA256);

        $this->assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '230152',
                2,
                26213400
            )
        ); // 26213398

        $this->assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '064978',
                2,
                26213400
            )
        ); // 26213399

        $this->assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '758576',
                2,
                26213400
            )
        ); // 26213400

        $this->assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '935741',
                2,
                26213400
            )
        ); // 26213401

        $this->assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '044590',
                2,
                26213400
            )
        ); // 26213402

        $this->assertFalse(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '576276',
                2,
                26213400
            )
        ); // 26213403

        $this->assertFalse(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '152688',
                2,
                26213400
            )
        ); // 26213397
    }

    public function testVerifiesSha256KeysNewer()
    {
        $this->google2fa->setAlgorithm(Google2FAConstants::SHA256);

        $this->assertFalse(
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '758576',
                26213401,
                2,
                26213400
            )
        ); // 26213400
        $this->assertFalse(
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '935741',
                26213401,
                2,
                26213400
            )
        ); // 26213401
        $this->assertEquals(
            26213402,
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '044590',
                26213401,
                2,
                26213400
            )
        ); // 26213402
        $this->assertFalse(
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '576276',
                26213401,
                2,
                26213400
            )
        ); // 26213403

        $this->assertEquals(
            26213400,
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '758576',
                null,
                2,
                26213400
            )
        ); // 26213400
        $this->assertEquals(
            26213401,
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '935741',
                null,
                2,
                26213400
            )
        ); // 26213401
        $this->assertEquals(
            26213402,
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '044590',
                null,
                2,
                26213400
            )
        ); // 26213402
        $this->assertFalse(
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '576276',
                null,
                2,
                26213400
            )
        ); // 26213403
    }

    public function testVerifiesSha512Keys()
    {
        // $ts 26213400 with KEY_REGENERATION 30 seconds is
        // timestamp 786402000, which is 1994-12-02 21:00:00 UTC

        $this->google2fa->setAlgorithm(Google2FAConstants::SHA512);

        $this->assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '772377',
                2,
                26213400
            )
        ); // 26213398
        $this->assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '048034',
                2,
                26213400
            )
        ); // 26213399
        $this->assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '752139',
                2,
                26213400
            )
        ); // 26213400
        $this->assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '572238',
                2,
                26213400
            )
        ); // 26213401
        $this->assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '424074',
                2,
                26213400
            )
        ); // 26213402

        $this->assertFalse(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '237162',
                2,
                26213400
            )
        ); // 26213403
        $this->assertFalse(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '705476',
                2,
                26213400
            )
        ); // 26213397
    }

    public function testVerifiesSha512KeysNewer()
    {
        $this->google2fa->setAlgorithm(Google2FAConstants::SHA512);

        $this->assertFalse(
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '752139',
                26213401,
                2,
                26213400
            )
        ); // 26213400
        $this->assertFalse(
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '572238',
                26213401,
                2,
                26213400
            )
        ); // 26213401
        $this->assertEquals(
            26213402,
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '424074',
                26213401,
                2,
                26213400
            )
        ); // 26213402
        $this->assertFalse(
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '237162',
                26213401,
                2,
                26213400
            )
        ); // 26213403

        $this->assertEquals(
            26213400,
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '752139',
                null,
                2,
                26213400
            )
        ); // 26213400
        $this->assertEquals(
            26213401,
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '572238',
                null,
                2,
                26213400
            )
        ); // 26213401
        $this->assertEquals(
            26213402,
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '424074',
                null,
                2,
                26213400
            )
        ); // 26213402
        $this->assertFalse(
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '237162',
                null,
                2,
                26213400
            )
        ); // 26213403
    }

    public function testRemovesInvalidCharsFromSecret()
    {
        $this->assertEquals(
            Constants::SECRET,
            $this->google2fa->removeInvalidChars(Constants::SECRET . '!1-@@@')
        );
    }

    public function testConvertsToBase32()
    {
        $this->assertEquals(
            'KBZGCZ3NMFJFQ',
            $this->google2fa->toBase32('PragmaRX')
        );
    }

    public function testSetsTheWindow()
    {
        $this->google2fa->setWindow(6);

        $this->assertEquals(6, $this->google2fa->getWindow());

        $this->assertEquals(1, $this->google2fa->getWindow(1));

        $this->google2fa->setWindow(0);

        $this->assertFalse(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '558854',
                null,
                26213400
            )
        );

        $this->google2fa->setWindow(2);

        $this->assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '558854',
                null,
                26213400
            )
        );
        $this->assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '558854',
                null,
                26213399
            )
        );
        $this->assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '558854',
                null,
                26213398
            )
        );
        $this->assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '558854',
                null,
                26213396
            )
        );
        $this->assertFalse(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '558854',
                null,
                26213395
            )
        );
    }

    public function testSetsTheSecret()
    {
        $this->assertFalse(
            $this->google2fa->verify('558854', Constants::WRONG_SECRET)
        );

        $this->google2fa->setWindow(2);

        $this->assertTrue(
            $this->google2fa->verify(
                '558854',
                Constants::SECRET,
                null,
                26213400
            )
        );

        $this->google2fa->setSecret(Constants::SECRET);

        $this->assertTrue(
            $this->google2fa->verify('558854', null, null, 26213400)
        );
    }

    public function testGetsAlgorithm()
    {
        $this->google2fa->setAlgorithm('sha1');

        $this->assertEquals('sha1', $this->google2fa->getAlgorithm());
        $this->assertEquals(Google2FAConstants::SHA1, $this->google2fa->getAlgorithm());

        $this->google2fa->setAlgorithm('sha256');

        $this->assertEquals('sha256', $this->google2fa->getAlgorithm());
        $this->assertEquals(Google2FAConstants::SHA256, $this->google2fa->getAlgorithm());

        $this->google2fa->setAlgorithm('sha512');

        $this->assertEquals('sha512', $this->google2fa->getAlgorithm());
        $this->assertEquals(Google2FAConstants::SHA512, $this->google2fa->getAlgorithm());
    }

    /**
     * @expectedException  \PragmaRX\Google2FA\Exceptions\InvalidAlgorithmException
     */
    public function testSetWrongAlgorithm()
    {
        $this->google2fa->setAlgorithm('md5');

        $this->assertEquals('sha1', $this->google2fa->getAlgorithm());
        $this->assertEquals(Google2FAConstants::SHA1, $this->google2fa->getAlgorithm());
    }

    public function testGetsKeyRegeneration()
    {
        $this->google2fa->setKeyRegeneration(11);

        $this->assertEquals(11, $this->google2fa->getKeyRegeneration());
    }

    public function testGetsOtpLength()
    {
        $this->google2fa->setOneTimePasswordLength(7);

        $this->assertEquals(7, $this->google2fa->getOneTimePasswordLength());
    }

    public function testGeneratesPasswordsInManyDifferentSizes()
    {
        $this->google2fa->setWindow(2);

        $this->google2fa->setOneTimePasswordLength(6);

        $this->assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '558854',
                null,
                26213400
            )
        );

        $this->google2fa->setOneTimePasswordLength(7);

        $this->assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '8981084',
                null,
                26213400
            )
        );
    }

    /**
     * @expectedException \PragmaRX\Google2FA\Exceptions\SecretKeyTooShortException
     */
    public function testShortSecretKey()
    {
        $this->google2fa->setEnforceGoogleAuthenticatorCompatibility(false);

        $this->google2fa->verifyKey(
            Constants::SHORT_SECRET,
            '558854',
            null,
            26213400
        );
    }

    /**
     * @expectedException \PragmaRX\Google2FA\Exceptions\InvalidCharactersException
     */
    public function testValidateKey()
    {
        $this->assertTrue(
            is_numeric($this->google2fa->getCurrentOtp(Constants::SECRET))
        );

        $this->google2fa->setEnforceGoogleAuthenticatorCompatibility(false);

        $this->google2fa->getCurrentOtp(Constants::INVALID_SECRET);
    }

    /**
     * @expectedException \PragmaRX\Google2FA\Exceptions\Google2FAException
     */
    public function testThrowsBaseException()
    {
        $this->throwSecretKeyTooShortException();
    }

    /**
     * @expectedException \PragmaRX\Google2FA\Exceptions\Contracts\Google2FA
     */
    public function testThrowsBaseExceptionContract()
    {
        $this->throwSecretKeyTooShortException();
    }

    /**
     * @expectedException \PragmaRX\Google2FA\Exceptions\SecretKeyTooShortException
     */
    public function testThrowsSecretKeyTooShortException()
    {
        $this->throwSecretKeyTooShortException();
    }

    /**
     * @expectedException \PragmaRX\Google2FA\Exceptions\Contracts\SecretKeyTooShort
     */
    public function testThrowsSecretKeyTooShortExceptionContract()
    {
        $this->throwSecretKeyTooShortException();
    }

    /**
     * @expectedException \PragmaRX\Google2FA\Exceptions\Contracts\IncompatibleWithGoogleAuthenticator
     */
    public function testThrowsIncompatibleWithGoogleAuthenticatorExceptionInterface()
    {
        $this->throwIncompatibleWithGoogleAuthenticatorException();
    }

    public function throwSecretKeyTooShortException()
    {
        $this->google2fa->setEnforceGoogleAuthenticatorCompatibility(false);

        $this->google2fa->verifyKey(
            Constants::SHORT_SECRET, // <------------- BUG
            '558854',
            null,
            26213400
        );
    }

    public function throwIncompatibleWithGoogleAuthenticatorException()
    {
        $this->google2fa
            ->setEnforceGoogleAuthenticatorCompatibility(true)
            ->generateSecretKey(17);

        $this->assertEquals(
            17,
            strlen(
                $this->google2fa
                    ->setEnforceGoogleAuthenticatorCompatibility(false)
                    ->generateSecretKey(17)
            )
        );
    }
}
