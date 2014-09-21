<?php

namespace spec\PragmaRX\Google2FA;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use PragmaRX\Google2FA\Google2FA;

class Google2FASpec extends ObjectBehavior
{
	public $secret = 'ADUMJO5634NPDEKW';

	public $url = 'https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth%3A%2F%2Ftotp%2FPragmaRX%3Aacr%2Bpragmarx%40antoniocarlosribeiro.com%3Fsecret%3DADUMJO5634NPDEKW%26issuer%3DPragmaRX';

    function it_is_initializable()
    {
        $this->shouldHaveType('PragmaRX\Google2FA\Google2FA');
    }

	function it_generates_a_valid_secret_key()
	{
		$this->generateSecretKey()->shouldHaveLength(16);

		$this->generateSecretKey()->shouldBeAmongst(Google2FA::VALID_FOR_B32);
	}

	function it_gets_valid_timestamps()
	{
		$this->getTimestamp()->shouldBeValidTimestamp();
	}

	function it_decodes_base32_strings()
	{
		$this->base32Decode($this->secret)->shouldBeBinaryEquals(chr(232) . chr(196) . chr(187) . chr(190) . chr(223) . chr(26) . chr(241) . chr(145) . chr(86));
	}

	function it_creates_a_one_time_password()
	{
		$this->getCurrentOtp($this->secret)->shouldHaveLength(6);
	}

	function it_verifies_a_key()
	{
		// 26213400 = Human time (GMT): Sat, 31 Oct 1970 09:30:00 GMT

		$this->verifyKey($this->secret, '410272', 4, 26213400)->shouldBe(true);
	}

	function it_removes_invalid_chars_from_secret()
	{
		$this->removeInvalidChars($this->secret . '!1-@@@')->shouldBe($this->secret);
	}

	function it_creates_a_qr_code()
	{
		$this->getQRCodeGoogleUrl('PragmaRX', 'acr+pragmarx@antoniocarlosribeiro.com', $this->secret)->shouldBe($this->url);
	}

	public function getMatchers()
	{
		return [
			'haveLength' => function($subject, $key)
			{
				return strlen($subject) == $key;
			},

			'beAmongst' => function($subject, $key)
			{
				return preg_replace('/[^'.$key.']/', '', $subject) === $subject;
			},

		    'beValidTimestamp' => function($timestamp)
		    {
			    return ((string) (int) $timestamp === (string) (int) $timestamp)
						&& ($timestamp <= PHP_INT_MAX)
						&& ($timestamp >= ~PHP_INT_MAX);
		    },

		    'beBinaryEquals' => function($one, $two)
		    {
			    $two = chr(0) . $two;

				$s1 = '';
			    $s2 = '';

			    for ($x = 0; $x < strlen($one); $x++)
			    {
				    $s1 .= ord($one[$x]);
			    }

			    for ($x = 0; $x < strlen($two); $x++)
			    {
				    $s2 .= ord($two[$x]);
			    }

			    return $s1 === $s2;
		    },

		];
	}

}
