<?php

declare(strict_types=1);

namespace PragmaRX\Google2FA\Tests;

use PHPUnit\Framework\Assert;
use PHPUnit\Framework\TestCase;
use PragmaRX\Google2FA\Google2FA;
use PragmaRX\Google2FA\Support\Constants as Google2FAConstants;

class Google2FATest extends TestCase
{
    public Google2FA $google2fa;

    public function setUp(): void
    {
        $this->google2fa = new Google2FA();
    }

    public function testIsInitializable(): void
    {
        Assert::assertInstanceOf(Google2FA::class, $this->google2fa);
    }

    public function testGeneratesAValidSecretKey(): void
    {
        Assert::assertEquals(16, strlen($this->google2fa->generateSecretKey()));

        Assert::assertEquals(
            32,
            strlen($this->google2fa->generateSecretKey(32)),
        );

        Assert::assertStringStartsWith(
            'MFXHI',
            $this->google2fa->generateSecretKey(59, 'ant'),
        );

        Assert::assertStringStartsWith(
            'MFXHI',
            $this->google2fa->generateSecretKey(59, 'ant'),
        );

        Assert::assertEquals(
            $key = $this->google2fa->generateSecretKey(),
            preg_replace(
                '/[^' . Google2FAConstants::VALID_FOR_B32 . ']/',
                '',
                $key,
            ),
        );
    }

    public function testGeneratesASecretKeysCompatibleWithGoogleAuthenticator(): void
    {
        Assert::assertEquals(
            $size = 16,
            strlen(
                $this->google2fa
                    ->setEnforceGoogleAuthenticatorCompatibility(true)
                    ->generateSecretKey($size),
            ),
        ); /// minimum = 128 bits
        Assert::assertEquals(
            $size = 20,
            strlen(
                $this->google2fa
                    ->setEnforceGoogleAuthenticatorCompatibility(false)
                    ->generateSecretKey($size),
            ),
        ); /// recommended = 160 bits - not compatible
        Assert::assertEquals(
            $size = 32,
            strlen(
                $this->google2fa
                    ->setEnforceGoogleAuthenticatorCompatibility(true)
                    ->generateSecretKey($size),
            ),
        ); /// recommended = 256 bits - compatible
        Assert::assertEquals(
            $size = 64,
            strlen(
                $this->google2fa
                    ->setEnforceGoogleAuthenticatorCompatibility(true)
                    ->generateSecretKey($size),
            ),
        );
        Assert::assertEquals(
            $size = 128,
            strlen(
                $this->google2fa
                    ->setEnforceGoogleAuthenticatorCompatibility(true)
                    ->generateSecretKey($size),
            ),
        );
    }

    public function testGeneratesASecretKeysGenerationSize(): void
    {
        // 128 bits are allowed
        Assert::assertEquals(
            $size = 16,
            strlen($this->google2fa->generateSecretKey($size)),
        ); /// minimum = 128 bits

        // anything below 128 bits are NOT allowed
        $this->expectException(
            \PragmaRX\Google2FA\Exceptions\SecretKeyTooShortException::class,
        );

        Assert::assertEquals(
            $size = 2,
            strlen($this->google2fa->generateSecretKey($size)),
        ); /// minimum = 128 bits
        Assert::assertEquals(
            $size = 4,
            strlen($this->google2fa->generateSecretKey($size)),
        ); /// minimum = 128 bits
        Assert::assertEquals(
            $size = 8,
            strlen($this->google2fa->generateSecretKey($size)),
        ); /// minimum = 128 bits
    }

    public function testGeneratesASecretKeysNotCompatibleWithGoogleAuthenticator(): void
    {
        $this->expectException(
            \PragmaRX\Google2FA\Exceptions\IncompatibleWithGoogleAuthenticatorException::class,
        );
        Assert::assertEquals(
            $size = 15,
            strlen(
                $this->google2fa
                    ->setEnforceGoogleAuthenticatorCompatibility(true)
                    ->generateSecretKey($size),
            ),
        );

        $this->expectException(
            \PragmaRX\Google2FA\Exceptions\IncompatibleWithGoogleAuthenticatorException::class,
        );
        Assert::assertEquals(
            $size = 17,
            strlen(
                $this->google2fa
                    ->setEnforceGoogleAuthenticatorCompatibility(true)
                    ->generateSecretKey($size),
            ),
        );

        $this->expectException(
            \PragmaRX\Google2FA\Exceptions\IncompatibleWithGoogleAuthenticatorException::class,
        );
        Assert::assertEquals(
            $size = 21,
            strlen(
                $this->google2fa
                    ->setEnforceGoogleAuthenticatorCompatibility(true)
                    ->generateSecretKey($size),
            ),
        );
    }

    public function testConvertsInvalidCharsToBase32(): void
    {
        $converted = $this->google2fa->generateBase32RandomKey(
            16,
            '1234' .
                chr(250) .
                chr(251) .
                chr(252) .
                chr(253) .
                chr(254) .
                chr(255),
        );

        $valid = preg_replace(
            '/[^' . Google2FAConstants::VALID_FOR_B32 . ']/',
            '',
            $converted,
        );

        Assert::assertEquals($converted, $valid);
    }

    public function testGetsValidTimestamps(): void
    {
        $ts = $this->google2fa->getTimestamp();

        Assert::assertLessThanOrEqual(PHP_INT_MAX, $ts);

        Assert::assertGreaterThanOrEqual(~PHP_INT_MAX, $ts);
    }

    public function testDecodesBase32Strings(): void
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

        Assert::assertEquals(
            $result,
            $this->google2fa->base32Decode(Constants::SECRET),
        );
    }

    public function testCreatesAOneTimePassword(): void
    {
        Assert::assertEquals(
            6,
            strlen($this->google2fa->getCurrentOtp(Constants::SECRET)),
        );
    }

    public function testVerifiesKeys(): void
    {
        // $ts 26213400 with KEY_REGENERATION 30 seconds is
        // timestamp 786402000, which is 1994-12-02 21:00:00 UTC

        Assert::assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '558854',
                2,
                26213400,
            ),
        ); // 26213398
        Assert::assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '981084',
                2,
                26213400,
            ),
        ); // 26213399
        Assert::assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '512396',
                2,
                26213400,
            ),
        ); // 26213400
        Assert::assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '410272',
                2,
                26213400,
            ),
        ); // 26213401
        Assert::assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '239815',
                2,
                26213400,
            ),
        ); // 26213402

        Assert::assertFalse(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '313366',
                2,
                26213400,
            ),
        ); // 26213403
        Assert::assertFalse(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '093183',
                2,
                26213400,
            ),
        ); // 26213397
    }

    public function testVerifiesKeysNewer(): void
    {
        Assert::assertFalse(
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '512396',
                null, /// first time user gets in
            ),
        ); // 26213400
        Assert::assertTrue(
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '512396',
                null, /// first time user gets in
                2,
                26213400,
            ),
        ); // 26213400
        Assert::assertFalse(
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '512396',
                26213401,
                2,
                26213400,
            ),
        ); // 26213400
        Assert::assertFalse(
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '410272',
                26213401,
                2,
                26213400,
            ),
        ); // 26213401
        Assert::assertEquals(
            26213402,
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '239815',
                26213401,
                2,
                26213400,
            ),
        ); // 26213402
        Assert::assertFalse(
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '313366',
                26213401,
                2,
                26213400,
            ),
        ); // 26213403

        Assert::assertEquals(
            26213400,
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '512396',
                null,
                2,
                26213400,
            ),
        ); // 26213400
        Assert::assertEquals(
            26213401,
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '410272',
                null,
                2,
                26213400,
            ),
        ); // 26213401
        Assert::assertEquals(
            26213402,
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '239815',
                null,
                2,
                26213400,
            ),
        ); // 26213402
        Assert::assertFalse(
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '313366',
                null,
                2,
                26213400,
            ),
        ); // 26213403
    }

    public function testVerifiesSha256Keys(): void
    {
        // $ts 26213400 with KEY_REGENERATION 30 seconds is
        // timestamp 786402000, which is 1994-12-02 21:00:00 UTC

        $this->google2fa->setAlgorithm(Google2FAConstants::SHA256);

        Assert::assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '230152',
                2,
                26213400,
            ),
        ); // 26213398

        Assert::assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '064978',
                2,
                26213400,
            ),
        ); // 26213399

        Assert::assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '758576',
                2,
                26213400,
            ),
        ); // 26213400

        Assert::assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '935741',
                2,
                26213400,
            ),
        ); // 26213401

        Assert::assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '044590',
                2,
                26213400,
            ),
        ); // 26213402

        Assert::assertFalse(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '576276',
                2,
                26213400,
            ),
        ); // 26213403

        Assert::assertFalse(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '152688',
                2,
                26213400,
            ),
        ); // 26213397
    }

    public function testVerifiesSha256KeysNewer(): void
    {
        $this->google2fa->setAlgorithm(Google2FAConstants::SHA256);

        Assert::assertFalse(
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '758576',
                26213401,
                2,
                26213400,
            ),
        ); // 26213400
        Assert::assertFalse(
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '935741',
                26213401,
                2,
                26213400,
            ),
        ); // 26213401
        Assert::assertEquals(
            26213402,
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '044590',
                26213401,
                2,
                26213400,
            ),
        ); // 26213402
        Assert::assertFalse(
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '576276',
                26213401,
                2,
                26213400,
            ),
        ); // 26213403

        Assert::assertEquals(
            26213400,
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '758576',
                null,
                2,
                26213400,
            ),
        ); // 26213400
        Assert::assertEquals(
            26213401,
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '935741',
                null,
                2,
                26213400,
            ),
        ); // 26213401
        Assert::assertEquals(
            26213402,
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '044590',
                null,
                2,
                26213400,
            ),
        ); // 26213402
        Assert::assertFalse(
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '576276',
                null,
                2,
                26213400,
            ),
        ); // 26213403
    }

    public function testVerifiesSha512Keys(): void
    {
        // $ts 26213400 with KEY_REGENERATION 30 seconds is
        // timestamp 786402000, which is 1994-12-02 21:00:00 UTC

        $this->google2fa->setAlgorithm(Google2FAConstants::SHA512);

        Assert::assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '772377',
                2,
                26213400,
            ),
        ); // 26213398
        Assert::assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '048034',
                2,
                26213400,
            ),
        ); // 26213399
        Assert::assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '752139',
                2,
                26213400,
            ),
        ); // 26213400
        Assert::assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '572238',
                2,
                26213400,
            ),
        ); // 26213401
        Assert::assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '424074',
                2,
                26213400,
            ),
        ); // 26213402

        Assert::assertFalse(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '237162',
                2,
                26213400,
            ),
        ); // 26213403
        Assert::assertFalse(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '705476',
                2,
                26213400,
            ),
        ); // 26213397
    }

    public function testVerifiesSha512KeysNewer(): void
    {
        $this->google2fa->setAlgorithm(Google2FAConstants::SHA512);

        Assert::assertFalse(
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '752139',
                26213401,
                2,
                26213400,
            ),
        ); // 26213400
        Assert::assertFalse(
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '572238',
                26213401,
                2,
                26213400,
            ),
        ); // 26213401
        Assert::assertEquals(
            26213402,
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '424074',
                26213401,
                2,
                26213400,
            ),
        ); // 26213402
        Assert::assertFalse(
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '237162',
                26213401,
                2,
                26213400,
            ),
        ); // 26213403

        Assert::assertEquals(
            26213400,
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '752139',
                null,
                2,
                26213400,
            ),
        ); // 26213400
        Assert::assertEquals(
            26213401,
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '572238',
                null,
                2,
                26213400,
            ),
        ); // 26213401
        Assert::assertEquals(
            26213402,
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '424074',
                null,
                2,
                26213400,
            ),
        ); // 26213402
        Assert::assertFalse(
            $this->google2fa->verifyKeyNewer(
                Constants::SECRET,
                '237162',
                null,
                2,
                26213400,
            ),
        ); // 26213403
    }

    public function testRemovesInvalidCharsFromSecret(): void
    {
        Assert::assertEquals(
            Constants::SECRET,
            $this->google2fa->removeInvalidChars(Constants::SECRET . '!1-@@@'),
        );
    }

    public function testConvertsToBase32(): void
    {
        Assert::assertEquals(
            'KBZGCZ3NMFJFQ',
            $this->google2fa->toBase32('PragmaRX'),
        );
    }

    public function testSetsTheWindow(): void
    {
        $this->google2fa->setWindow(6);

        Assert::assertEquals(6, $this->google2fa->getWindow());

        Assert::assertEquals(1, $this->google2fa->getWindow(1));

        $this->google2fa->setWindow(0);

        Assert::assertFalse(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '558854',
                null,
                26213400,
            ),
        );

        $this->google2fa->setWindow(2);

        Assert::assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '558854',
                null,
                26213400,
            ),
        );
        Assert::assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '558854',
                null,
                26213399,
            ),
        );
        Assert::assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '558854',
                null,
                26213398,
            ),
        );
        Assert::assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '558854',
                null,
                26213396,
            ),
        );
        Assert::assertFalse(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '558854',
                null,
                26213395,
            ),
        );
    }

    public function testSetsTheSecret(): void
    {
        Assert::assertFalse(
            $this->google2fa->verify('558854', Constants::WRONG_SECRET),
        );

        $this->google2fa->setWindow(2);

        Assert::assertTrue(
            $this->google2fa->verify(
                '558854',
                Constants::SECRET,
                null,
                26213400,
            ),
        );

        $this->google2fa->setSecret(Constants::SECRET);
    }

    public function testGetsAlgorithm(): void
    {
        $this->google2fa->setAlgorithm('sha1');

        Assert::assertEquals('sha1', $this->google2fa->getAlgorithm());
        Assert::assertEquals(
            Google2FAConstants::SHA1,
            $this->google2fa->getAlgorithm(),
        );

        $this->google2fa->setAlgorithm('sha256');

        Assert::assertEquals('sha256', $this->google2fa->getAlgorithm());
        Assert::assertEquals(
            Google2FAConstants::SHA256,
            $this->google2fa->getAlgorithm(),
        );

        $this->google2fa->setAlgorithm('sha512');

        Assert::assertEquals('sha512', $this->google2fa->getAlgorithm());
        Assert::assertEquals(
            Google2FAConstants::SHA512,
            $this->google2fa->getAlgorithm(),
        );
    }

    public function testSetWrongAlgorithm(): void
    {
        $this->expectException(
            \PragmaRX\Google2FA\Exceptions\InvalidAlgorithmException::class,
        );

        $this->google2fa->setAlgorithm('md5');

        Assert::assertEquals('sha1', $this->google2fa->getAlgorithm());
        Assert::assertEquals(
            Google2FAConstants::SHA1,
            $this->google2fa->getAlgorithm(),
        );
    }

    public function testGetsKeyRegeneration(): void
    {
        $this->google2fa->setKeyRegeneration(11);

        Assert::assertEquals(11, $this->google2fa->getKeyRegeneration());
    }

    public function testGetsOtpLength(): void
    {
        $this->google2fa->setOneTimePasswordLength(7);

        Assert::assertEquals(7, $this->google2fa->getOneTimePasswordLength());
    }

    public function testGeneratesPasswordsInManyDifferentSizes(): void
    {
        $this->google2fa->setWindow(2);

        $this->google2fa->setOneTimePasswordLength(6);

        Assert::assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '558854',
                null,
                26213400,
            ),
        );

        $this->google2fa->setOneTimePasswordLength(7);

        Assert::assertTrue(
            $this->google2fa->verifyKey(
                Constants::SECRET,
                '8981084',
                null,
                26213400,
            ),
        );
    }

    public function testShortSecretKey(): void
    {
        $this->expectException(
            \PragmaRX\Google2FA\Exceptions\SecretKeyTooShortException::class,
        );

        $this->google2fa->setEnforceGoogleAuthenticatorCompatibility(false);

        $this->google2fa->verifyKey(
            Constants::SHORT_SECRET,
            '558854',
            null,
            26213400,
        );
    }

    public function testValidateKey(): void
    {
        $this->expectException(
            \PragmaRX\Google2FA\Exceptions\InvalidCharactersException::class,
        );

        Assert::assertTrue(
            is_numeric($this->google2fa->getCurrentOtp(Constants::SECRET)),
        );

        $this->google2fa->setEnforceGoogleAuthenticatorCompatibility(false);

        $this->google2fa->getCurrentOtp(Constants::INVALID_SECRET);
    }

    public function testThrowsBaseException(): void
    {
        $this->expectException(
            \PragmaRX\Google2FA\Exceptions\Google2FAException::class,
        );

        $this->throwSecretKeyTooShortException();
    }

    public function testThrowsBaseExceptionContract(): void
    {
        $this->expectException(
            \PragmaRX\Google2FA\Exceptions\Contracts\Google2FA::class,
        );

        $this->throwSecretKeyTooShortException();
    }

    public function testThrowsSecretKeyTooShortException(): void
    {
        $this->expectException(
            \PragmaRX\Google2FA\Exceptions\SecretKeyTooShortException::class,
        );

        $this->throwSecretKeyTooShortException();
    }

    public function testThrowsSecretKeyTooShortExceptionWhenVerifyingCode(): void
    {
        $this->expectException(
            \PragmaRX\Google2FA\Exceptions\SecretKeyTooShortException::class,
        );

        $this->google2fa->verify('558854', '', null, 26213400);
    }

    public function testThrowsSecretKeyTooShortExceptionContract(): void
    {
        $this->expectException(
            \PragmaRX\Google2FA\Exceptions\Contracts\SecretKeyTooShort::class,
        );

        $this->throwSecretKeyTooShortException();
    }

    public function testThrowsIncompatibleWithGoogleAuthenticatorExceptionInterface(): void
    {
        $this->expectException(
            \PragmaRX\Google2FA\Exceptions\Contracts\IncompatibleWithGoogleAuthenticator::class,
        );

        $this->throwIncompatibleWithGoogleAuthenticatorException();
    }

    public function throwSecretKeyTooShortException(): void
    {
        $this->google2fa->setEnforceGoogleAuthenticatorCompatibility(false);

        $this->google2fa->verifyKey(
            Constants::SHORT_SECRET, // <------------- BUG
            '558854',
            null,
            26213400,
        );
    }

    public function throwIncompatibleWithGoogleAuthenticatorException(): void
    {
        $this->google2fa
            ->setEnforceGoogleAuthenticatorCompatibility(true)
            ->generateSecretKey(17);

        Assert::assertEquals(
            17,
            strlen(
                $this->google2fa
                    ->setEnforceGoogleAuthenticatorCompatibility(false)
                    ->generateSecretKey(17),
            ),
        );
    }

    public function testOoathTotpThrowsSecretKeyTooShortException(): void
    {
        $this->expectException(
            \PragmaRX\Google2FA\Exceptions\SecretKeyTooShortException::class,
        );

        $this->google2fa->oathTotp('', 0);
    }

    public function testOathTruncateThrowsInvalidHashException(): void
    {
        $this->expectException(
            \PragmaRX\Google2FA\Exceptions\InvalidHashException::class,
        );

        $this->google2fa->oathTruncate('foo');
    }
}
