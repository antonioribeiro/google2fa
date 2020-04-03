<?php

namespace PragmaRX\Google2FA\Tests;

/**
 * @mixin \PHPUnit\Framework\TestCase
 */
trait TestCaseTypeHintTrait
{
    protected function setUp(): void
    {
        call_user_func([$this, 'setUpCompat']);
    }
}
