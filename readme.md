# Laravel Stats SDK

[![Latest Stable Version](https://poser.pugx.org/pragmarx/sdk/v/stable.png)](https://packagist.org/packages/pragmarx/sdk) [![License](https://poser.pugx.org/pragmarx/sdk/license.png)](https://packagist.org/packages/pragmarx/sdk)

###SDK gathers a lot of information from your requests to identify and store:

## Requirements

- Laravel 4.1+
- PHP 5.3.7+
- Package "geoip/geoip":"~1.14" (If you are planning to store Geo IP information)

## Installing

Require the `sdk` package by **executing** the following command in your command line:

    composer require "pragmarx/sdk":"0.6.*"

**Or** add to your composer.json:

    "require": {
        "pragmarx/sdk": "0.6.*"
    }

And execute

    composer update

Add the service provider to your app/config/app.php:

    'PragmaRX\SDK\Vendor\Laravel\ServiceProvider',

Create the migration:

    php artisan sdk:tables

Migrate it

    php artisan migrate

Publish sdk configuration:

    php artisan config:publish pragmarx/sdk

Create the UA Parser regex file (every time you run `composer update` you must also execute this command):

    php artisan sdk:updateparser

And edit the file `app/config/packages/pragmarx/sdk/config.php` to enable SDK.

    'enabled' => true,

Note that the logging function is disabled by default, because it may write too much data to your database, but you can enable it by changing:

    'log_enabled' => true,

If you are planning to store Geo IP information, also install the geoip package:

    composer require "geoip/geoip":"~1.14"

And make sure you don't have the PHP module installed. This is a Debian/Ubuntu example:

	sudo apt-get purge php5-geoip

## Database Connections & Query Logs

If you are planning to store your query logs, to avoid recursion while logging SQL queries, you will need to create a different database connection for it:

This is a main connection:

	'postgresql' => [
		'driver'   => 'pgsql',
		'host'     => 'localhost',
		'database' => getenv('MAIN.DATABASE_NAME'),
		'username' => getenv('MAIN.DATABASE_USER'),
		'password' => getenv('MAIN.DATABASE_PASSWORD'),
		'charset'  => 'utf8',
		'prefix'   => '',
		'schema'   => 'public',
	],

This is the sdk connection pointing to the same database:

	'sdk' => [
		'driver'   => 'pgsql',
		'host'     => 'localhost',
		'database' => getenv('MAIN.DATABASE_NAME'),
		'username' => getenv('MAIN.DATABASE_USER'),
		'password' => getenv('MAIN.DATABASE_PASSWORD'),
		'charset'  => 'utf8',
		'prefix'   => '',
		'schema'   => 'public',
	],

On your `sdk/config.php` file, set the SDK connection to the one you created for it:

	'connection' => 'sdk',

And ignore this connection for SQL queries logging:

	'do_not_log_sql_queries_connections' => array(
		'sdk'
	),

You don't need to use a different database, but, since SDK may generate a huge number of records, this would be a good practice.

## Author

[Antonio Carlos Ribeiro](http://twitter.com/iantonioribeiro)

## License

SDK is licensed under the BSD 3-Clause License - see the `LICENSE` file for details

## Contributing

Pull requests and issues are more than welcome.
