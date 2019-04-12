<?php

namespace Yadahan\AuthenticationLog\Listeners;

use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Auth\Events\Login;
use Illuminate\Support\Facades\Log;
use Yadahan\AuthenticationLog\AuthenticationLog;
use Yadahan\AuthenticationLog\GeoLocateService;
use Yadahan\AuthenticationLog\Notifications\NewDevice;

class LogSuccessfulLogin
{
    const COOKIE = "adiv";

    /**
     * The request.
     *
     * @var \Illuminate\Http\Request
     */
    public $request;

    /**
     * Create the event listener.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     */
    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    /**
     * Handle the event.
     *
     * @param  Login  $event
     * @return void
     */
    public function handle(Login $event)
    {
        $user = $event->user;
        $ip = $this->request->ip();
        $userAgent = $this->request->userAgent();
        $remember = $event->remember;
        $guard = $event->guard;
        $session_key = session()->getId();
        $location = (new GeoLocateService)->getLocationByIpAddress($ip);

        $known = false;

        \DB::beginTransaction();
        try
        {
            $authenticationLog = new AuthenticationLog([
                'session_key' => $session_key,
                'ip_address' => $ip,
                'user_agent' => $userAgent,
                'flag_remember' => $remember,
                'guard' => $guard,
                'login_at' => Carbon::now(),
                'location' => $location,
            ]);

            if( $this->request->hasCookie( self::COOKIE ) )
            {
                $known = $user->authentications()->where( 'comparison_hash', $this->request->cookie( self::COOKIE ) )->first();
            }
            else
            {
                session()->push( self::COOKIE, $authenticationLog->getComparisonHash() );
            }

            $user->authentications()->save($authenticationLog);

            \DB::commit();
        }
        catch ( \Exception $e )
        {
            \DB::rollback();

            Log::error( $e );
            return ;
        }

        if ( !$known && config('authentication-log.notify')) {
            if( method_exists( $user, 'allowNewDeviceNotifications' ) && !$user->allowNewDeviceNotifications() )
                return ;

            $user->notify(new NewDevice($authenticationLog));
        }
    }
}
