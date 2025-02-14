<?php defined('SYSPATH') or die('No direct script access.');

abstract class Kohana_SSO {
	
	/**
	 * @var  string  SSO service name
	 */
	protected $sso_service;

	/**
	 * @var  array  SSO configuration
	 */
	protected $sso_config;
	
	protected $session;
	
	protected $request;

	/**
	 * Loads the SSO configuration.
	 *
	 * @return  void
	 * @uses    Kohana::config
	 */
	public function __construct()
	{
		$this->session = Session::instance();
		
		$this->request = Request::initial();
		
		// Load SSO config
        /* v3.2
        */
		$this->sso_config = Kohana::$config->load('oauth')->{$this->sso_service}; 
	}

	/**
	 * Returns a new SSO object.
	 *
	 * @param   string  $provider
	 * @param   string  $driver
	 * @return  SSO
	 */
	public static function factory($provider)
	{
		$class = 'SSO_Service_'.$provider;

		return new $class;
	}
	
	public function key($name)
	{
		return "sso_{$this->provider->name}_{$name}";
	}
	
	public function complete_signup(array $data)
	{
	    // passo 3 ele volta para aqui.
        
		$provider_field = $this->sso_service.'_id';
        // passo1
		$user = ORM::factory('user')->find_sso_user($provider_field, $data['user_data']);
        
		if ( ! $user->loaded())
		{
         
          // vai mandar para modules/sso/classes/kohana/sso/oauth.php line 78
			$this->session->set('complete_signup', serialize($data));
          
		}
		else
		{
		  // N�o achamos usu�rio temos que cadastra-lo ent�o
		  
			// Sign a previous registered user
			Auth::instance()->force_sso_login($user);
			
			return TRUE;
		}
	}

	abstract public function login();
	
}