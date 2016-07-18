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
    protected $defer = true;

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        $this->app->bind(
            'PragmaRX\Google2FA\Contracts\Google2FA',
            'PragmaRX\Google2FA\Google2FA'
        );
    }

    /**
     * Get the services provided by the provider.
     *
     * @return array
     */
    public function provides()
    {
        return ['PragmaRX\Google2FA\Contracts\Google2FA'];
    }
}
