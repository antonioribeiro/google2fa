<?php

namespace PragmaRX\Google2FA\Vendor\Laravel;

use Illuminate\Support\ServiceProvider as IlluminateServiceProvider;

class ServiceProvider extends IlluminateServiceProvider
{

	/**
	 * Indicates if loading of the provider is deferred.
	 *
	 * @var bool
	 */
	protected $defer = false;

	/**
	 * Register the service provider.
	 *
	 * @return void
	 */
	public function register()
	{
		$this->app->bind(
			$contract = 'PragmaRX\Google2FA\Contracts\Google2FA',
			$concrete = 'PragmaRX\Google2FA\Google2FA'
		);
	}

	/**
	 * Get the services provided by the provider.
	 *
	 * @return array
	 */
	public function provides()
	{
		return array('PragmaRX\Google2FA\Contracts\Google2FA');
	}

}
