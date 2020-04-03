<?php

namespace PragmaRX\Google2FA\Tests;

/**
 * @mixin \PHPUnit\Framework\TestCase
 */
trait TestCaseNoTypeHintTrait
{
    protected function setUp()
    {
        call_user_func([$this, 'setUpCompat']);
    }
}
