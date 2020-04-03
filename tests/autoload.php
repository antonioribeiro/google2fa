<?php

// Compatibility with PHPUnit 8.0
// We need to use "magic" trait \PragmaRX\Google2FA\Google2FA\TestCaseTrait
// and instead of setUp/tearDown method in test case
// we should have setUpCompat/tearDownCompat.
if (class_exists('PHPUnit\Runner\Version')
    && version_compare(PHPUnit\Runner\Version::id(), '8.0.0') >= 0
) {
    class_alias('\PragmaRX\Google2FA\Tests\TestCaseTypeHintTrait', 'PragmaRX\Google2FA\Tests\TestCaseTrait');
} else {
    class_alias('\PragmaRX\Google2FA\Tests\TestCaseNoTypeHintTrait', 'PragmaRX\Google2FA\Tests\TestCaseTrait');
}
