<?php namespace PragmaRX\Google2FA\Vendor\Laravel;
 
use PragmaRX\Google2FA\Google2FA;

use PragmaRX\Support\ServiceProvider as PragmaRXServiceProvider;

class ServiceProvider extends PragmaRXServiceProvider {

	/**
	 * Package Namespace
	 *
	 * @const string
	 */
	const PACKAGE_NAMESPACE = 'pragmarx/google2fa';

	/**
	 * Package name.
	 *
	 * @var
	 */
	protected $packageName = 'google2fa';

    /**
     * Indicates if loading of the provider is deferred.
     *
     * @var bool
     */
    protected $defer = true;

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
	    $this->app['pragmarx.google2fa'] = $this->app->share(function($app)
	    {
		    return new Google2FA();
	    });
    }

	/**
	 * Get the services provided by the provider.
	 *
	 * @return array
	 */
	public function provides()
	{
		return array('pragmarx.google2fa');
	}

}
