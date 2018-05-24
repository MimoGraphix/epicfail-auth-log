<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Notify New Device
    |--------------------------------------------------------------------------
    |
    | Here you define whether to receive notifications when logging from a new device.
    |
    */

    'notify' => env('AUTHENTICATION_LOG_NOTIFY', true),

    /*
    |--------------------------------------------------------------------------
    | Old Logs Clear
    |--------------------------------------------------------------------------
    |
    | When the clean-command is executed, all authentication logs older than
    | the number of days specified here will be deleted.
    |
    */

    'older' => 365,

    /*
    |--------------------------------------------------------------------------
    | Geolocation timeout
    |--------------------------------------------------------------------------
    |
    | Set the amount of time in seconds to wait for geolocation, if it exceeds
    | this then we ignore the location for performance reasons.
    |
    */

    'geolocation_timeout' => 2,

];
