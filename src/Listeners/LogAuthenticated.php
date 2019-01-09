<?php

namespace Yadahan\AuthenticationLog\Listeners;

use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Support\Facades\Log;
use Yadahan\AuthenticationLog\AuthenticationLog;
use Yadahan\AuthenticationLog\GeoLocateService;
use Yadahan\AuthenticationLog\Notifications\NewDevice;

class LogAuthenticated
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
     * @param  Authenticated  $event
     * @return void
     */
    public function handle(Authenticated $event)
    {
        $user = $event->user;
        $ip = $this->request->ip();
        $userAgent = $this->request->userAgent();
        $guard = $event->guard;
        $session_key = session()->getId();

		\DB::beginTransaction();
		try
		{
			$known = $user->activeAuthentications()
				->where( 'session_key', $session_key );

			if( $known->count() == 0 )
			{
				$_known = $user->activeAuthentications()
					->where( 'ip_address', $ip )
					->where( 'user_agent', $userAgent )
					->where( 'guard', $guard );

				$known = $_known->first();

				if( $known == null )
				{
					Log::error( 'What The FUCK just happed?' );
					return ;
				}

				// Remove duplicities because for some reason it sometimes happen
				$_known->where( 'id', '!=', $known->id )
					->where( 'login_at', $known->login_at )
					->delete();

				$known->session_key = $session_key;
			}
			else
			{
				$known = $known->first();

				$user->activeAuthentications()
					->where( 'ip_address', $ip )
					->where( 'user_agent', $userAgent )
					->where( 'guard', $guard )
					->where( 'id', '!=', $known->id )
					->where( 'login_at', $known->login_at )
					->delete();
			}

			$known->last_active = Carbon::now();
			$known->save();

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
