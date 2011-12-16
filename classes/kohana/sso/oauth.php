<?php defined('SYSPATH') or die('No direct script access.');

abstract class Kohana_SSO_OAuth extends SSO {
	
	/**
	 * @var  object  OAuth_Provider
	 */
	protected $provider;

	/**
	 * @var  object  OAuth_Consumer
	 */
	protected $consumer;

	/**
	 * @var  object  OAuth_Token
	 */
	protected $token;
	
	public function __construct()
	{
		parent::__construct();
		
		// Load the provider
		$this->provider = OAuth_Provider::factory($this->sso_service);

		// Load the consumer
        /*
        v.3.2
        */
        $service = $this->sso_service;
		$this->consumer = OAuth_Consumer::factory(Kohana::$config->load('oauth')->$service);

		if ($token = $this->session->get($this->key('access')))
		{
			// Make the access token available
			$this->token = $token;
		}
	}
	
	public function login()
	{
		// Attempt to complete signin
		if ($verifier = Arr::get($_REQUEST, 'oauth_verifier'))
		{
			if ( ! $token = $this->session->get($this->key('request')) OR $token->token !== Arr::get($_REQUEST, 'oauth_token'))
			{
				// Token is invalid
				$this->session->delete($this->key('request'));

				// Restart the login process
				$this->request->redirect($this->request->uri());
			}

			// Store the verifier in the token
			$token->verifier($verifier);

			// Exchange the request token for an access token
			$token = $this->provider->access_token($this->consumer, $token);

			// Store the access token
			$this->session->set($this->key('access'), $token);

			// Request token is no longer needed
			$this->session->delete($this->key('request'));
			
			try
			{
				$data = array(
					'user_data' => $this->provider->user_data($this->consumer, $token),
					'provider' => $this->provider->name,
				);
				
				if ($this->complete_signup($data) === TRUE)
				{
					return TRUE;
				}
				else
				{
					$this->request->redirect('');
				}
			}
			catch (Kohana_OAuth_Exception $e)
			{
				// Log the error and return false
				Kohana::$log->add(Log::ERROR, Kohana_Exception::text($e));
			    return FALSE;
			}
		}

		// We will need a callback URL for the user to return to
		$callback = $this->request->url(NULL, TRUE);
        
        $callback = Kohana::$config->load('site')->url.$callback;
		
        // Add the callback URL to the consumer
		$this->consumer->callback($callback);

		// Get a request token for the consumer
		$token = $this->provider->request_token($this->consumer, array('scope' => $this->sso_config['scopes']));

		// Store the token
		$this->session->set($this->key('request'), $token);

		// Redirect to the provider's login page
		$this->request->redirect($this->provider->authorize_url($token));
	}
	
}