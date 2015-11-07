<?php

namespace spec\PragmaRX\Google2FA;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class Google2FASpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType('PragmaRX\Google2FA\Google2FA');
    }
}
