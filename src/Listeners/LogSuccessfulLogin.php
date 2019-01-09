<?php

namespace Yadahan\AuthenticationLog\Listeners;

use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Auth\Events\Login;
use Yadahan\AuthenticationLog\AuthenticationLog;
use Yadahan\AuthenticationLog\GeoLocateService;
use Yadahan\AuthenticationLog\Notifications\NewDevice;

class LogSuccessfulLogin
{
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

		$known = $user->authentications()->whereIpAddress($ip)->whereUserAgent($userAgent)->first();

        $authenticationLog = new AuthenticationLog([
            'session_key' => $session_key,
            'ip_address' => $ip,
            'user_agent' => $userAgent,
            'flag_remember' => $remember,
            'guard' => $guard,
            'login_at' => Carbon::now(),
            'location' => $location,
        ]);

        $user->authentications()->save($authenticationLog);

        if ( !$known && config('authentication-log.notify')) {
        	if( method_exists( $user, 'allowNewDeviceNotifications' ) && !$user->allowNewDeviceNotifications() )
        		return ;

            if(config('authentication-log.has-email-validation') && $user->verified){
                $user->notify(new NewDevice($authenticationLog));
            }
            else $user->notify(new NewDevice($authenticationLog));
        }
    }
}
