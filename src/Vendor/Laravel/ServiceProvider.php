<?php namespace PragmaRX\Google2FA\Vendor\Laravel;
 
use PragmaRX\Google2FA\Google2FA;

use PragmaRX\Support\ServiceProvider as PragmaRXServiceProvider;

use Illuminate\Foundation\AliasLoader as IlluminateAliasLoader;

class ServiceProvider extends PragmaRXServiceProvider {

	/**
	 * Package Namespace
	 *
	 * @const string
	 */
	const PACKAGE_NAMESPACE = 'pragmarx/google2fa';

    /**
     * Indicates if loading of the provider is deferred.
     *
     * @var bool
     */
    protected $defer = true;

    /**
     * Bootstrap the application events.
     *
     * @return void
     */
    public function boot()
    {
        $this->package(self::PACKAGE_NAMESPACE, self::PACKAGE_NAMESPACE, __DIR__.'/../..');

        if( $this->app['config']->get(self::PACKAGE_NAMESPACE.'::create_google2fa_alias') )
        {
            IlluminateAliasLoader::getInstance()->alias(
                                                            $this->getConfig('google2fa_alias'),
                                                            'PragmaRX\Google2FA\Vendor\Laravel\Facade'
                                                        );
        }
    }

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
