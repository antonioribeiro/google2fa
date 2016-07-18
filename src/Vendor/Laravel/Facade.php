<?php

namespace PragmaRX\Google2FA\Vendor\Laravel;

use Illuminate\Support\Facades\Facade as IlluminateFacade;

class Facade extends IlluminateFacade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return 'PragmaRX\Google2FA\Contracts\Google2FA';
    }
}
