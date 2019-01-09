<?php

namespace Yadahan\AuthenticationLog;

use Illuminate\Database\Eloquent\Model;
use WhichBrowser\Constants\DeviceType;

class AuthenticationLog extends Model
{
    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected $table = 'authentication_log';

    /**
     * Indicates if the model should be timestamped.
     *
     * @var bool
     */
    public $timestamps = false;

    /**
     * The attributes that aren't mass assignable.
     *
     * @var array
     */
    protected $guarded = ['authenticatable_id', 'authenticatable_type'];

    /**
     * The attributes that should be cast to native types.
     *
     * @var array
     */
    protected $casts = [
        'last_active' => 'datetime',
        'login_at' => 'datetime',
        'logout_at' => 'datetime',
    ];

    /**
     * The attributes that should be hidden for arrays.
     *
     * @var array
     */
    protected $hidden = [
        'session_key',
    ];

	private $_parsedBrowser = null;

	/**
     * Get the authenticatable entity that the authentication log belongs to.
     */
    public function authenticatable()
    {
        return $this->morphTo();
    }

	/**
	 * @return \WhichBrowser\Parser
	 */
    public function parseUserAgent()
	{
		if( $this->_parsedBrowser )
			return $this->_parsedBrowser;

		$this->_parsedBrowser = new \WhichBrowser\Parser( $this->user_agent );

		return $this->_parsedBrowser;
	}

	public function isPC()
	{
		return $this->parseUserAgent()->isType( DeviceType::DESKTOP );
	}

	public function isMobile()
	{
		return $this->parseUserAgent()->isType( DeviceType::MOBILE, DeviceType::PDA );
	}

	public function isTablet()
	{
		return $this->parseUserAgent()->isType( DeviceType::TABLET );
	}

    public function getOs()
	{
		return $this->parseUserAgent()->os->toString();
	}

    public function getBrowser()
	{
		return $this->parseUserAgent()->browser->toString();
	}

	public function getLocation()
	{
		return $this->location;
	}

	public function isActual()
	{
		return $this->session_key == session()->getId();
	}
}
