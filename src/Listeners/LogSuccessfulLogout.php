<?php

namespace Yadahan\AuthenticationLog\Listeners;

use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Auth\Events\Logout;
use Illuminate\Support\Facades\Log;
use Yadahan\AuthenticationLog\AuthenticationLog;

class LogSuccessfulLogout
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
     * @param  Logout  $event
     * @return void
     */
    public function handle(Logout $event)
    {
        if( $event->user != null )
        {
			$user = $event->user;
			$ip = $this->request->ip();
			$userAgent = $this->request->userAgent();
			$guard = $event->guard;
			$session_key = session()->getId();

			\DB::beginTransaction();
			try
			{
				$authenticationLog = $user->activeAuthentications()
					->where( 'session_key', $session_key );

				if( $authenticationLog->count() == 0 )
				{
					$authenticationLog = $user->activeAuthentications()
						->where( 'ip_address', $ip )
						->where( 'user_agent', $userAgent )
						->where( 'guard', $guard );

					$authenticationLog = $authenticationLog->first();

					if( $authenticationLog == null )
					{
						$authenticationLog = new AuthenticationLog([
							'session_key' => $session_key,
							'ip_address' => $ip,
							'user_agent' => $userAgent,
							'guard' => $guard,
							'login_at' => Carbon::now(),
						]);
					}
				}
				else
				{
					$authenticationLog = $authenticationLog->first();
				}

				$authenticationLog->logout_at = Carbon::now();

				$user->authentications()->save($authenticationLog);

				\DB::commit();
			}
			catch ( \Exception $e )
			{
				\DB::rollback();

				Log::error( $e );
				return ;
			}
        }
    }
}
