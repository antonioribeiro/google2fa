# Google2FA

[![Latest Stable Version](https://poser.pugx.org/pragmarx/google2fa/v/stable.png)](https://packagist.org/packages/pragmarx/google2fa) [![License](https://poser.pugx.org/pragmarx/google2fa/license.png)](https://packagist.org/packages/pragmarx/google2fa)

###Google Two-Factor Authentication PHP Package

Google2FA is a PHP implementation of the Google Two-Factor Authentication Module, supporting the HMAC-Based One-time Password (HOTP) algorithm specified in [RFC 4226](https://tools.ietf.org/html/rfc4226) and the Time-based One-time Password (TOTP) algorithm specified in [RFC 6238](https://tools.ietf.org/html/rfc6238).

This package is agnostic, but also supports the Laravel Framework.

## Requirements

- PHP 5.3.7+

## Installing

Require the `google2fa` package by **executing** the following command in your command line:

    composer require "pragmarx/google2fa":"0.1.*"

**Or** add to your composer.json:

    "require": {
        "pragmarx/google2fa": "0.1.*"
    }

And execute

    composer update

## Installing on Laravel

Add the service provider and Facade alias to your `app/config/app.php` (Laravel 4.x) or `config/app.php` (Laravel 5.x):

    'PragmaRX\Google2FA\Vendor\Laravel\ServiceProvider',

    'Google2FA' => 'PragmaRX\Google2FA\Vendor\Laravel\Facade',

## Hot To Use It

Generate a secret key for your user and save it:

    $user = User::find(1);

    $user->google2fa_secret = Google2FA::generateSecretKey();

    $user->save();

Show the QR code to your user:

    $google2fa_url = Google2FA::getQRCodeGoogleUrl(
    	'YourCompany',
    	$user->email,
    	$user->google2fa_secret
    );

	{{ HTML::image($google2fa_url) }}

And they should see and scan the QR code to their applications:

![QRCode](https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth%3A%2F%2Ftotp%2FPragmaRX%3Aacr%2Bpragmarx%40antoniocarlosribeiro.com%3Fsecret%3DADUMJO5634NPDEKW%26issuer%3DPragmaRX)

And to verify, you just have to:

	$secret = Input::get('secret');

    $valid = Google2FA::verifyKey($user->google2fa_secret, $secret);

## Server Time

It's really important that you keep your server time in sync with some NTP server, on Ubuntu you can add this to the crontab:

    ntpdate ntp.ubuntu.com

## Demo

You can scan the QR code on [this page](https://antoniocarlosribeiro.com/technology/google2fa) with a Google Authenticator app and view view the code changing (almost) in real time.

## Google Authenticator Apps:

To use the two factor authentication, your user will have to install a Google Authenticator compatible app, those are some of the currently available:

* [Authy for iOS, Android, Chrome, OS X](https://www.authy.com/)
* [FreeOTP for iOS, Android and Peeble](https://fedorahosted.org/freeotp/)
* [FreeOTP for iOS, Android and Peeble](https://www.toopher.com/)
* [Google Authenticator for iOS](http://itunes.apple.com/us/app/google-authenticator/id388497605?mt=8")
* [Google Authenticator for Android](https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2")
* [Google Authenticator for Blackberry](https://m.google.com/authenticator")
* [Google Authenticator (port) on Windows app store](http://apps.microsoft.com/windows/en-us/app/google-authenticator/7ea6de74-dddb-47df-92cb-40afac4d38bb")

## Author

[Antonio Carlos Ribeiro](http://twitter.com/iantonioribeiro)

## License

Google2FA is licensed under the BSD 3-Clause License - see the `LICENSE` file for details

## Contributing

Pull requests and issues are more than welcome.
