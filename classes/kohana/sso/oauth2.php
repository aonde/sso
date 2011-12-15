<?php defined('SYSPATH') or die('No direct script access.');

abstract class Kohana_SSO_OAuth2 extends SSO {
	
	/**
	 * @var  object  OAuth2_Provider
	 */
	protected $provider;

	/**
	 * @var  object  OAuth2_Client
	 */
	protected $client;

	/**
	 * @var  object  OAuth2_Token
	 */
	protected $token;
	
	public function __construct()
	{
		parent::__construct();
		
		// Load the provider
		$this->provider = OAuth2_Provider::factory($this->sso_service);

		// Load the consumer
		$this->client = OAuth2_Client::factory(Kohana::config("oauth.{$this->sso_service}"));

		if ($token = $this->session->get($this->key('access')))
		{
			// Make the access token available
			$this->token = $token;
		}
	}
	
	public function login()
	{
		// Attempt to complete signin
		if ($code = Arr::get($_REQUEST, 'code'))
		{
			// Exchange the authorization code for an access token
			$token = $this->provider->access_token($this->client, $code);

			// Store the access token
			$this->session->set($this->key('access'), $token);

			// Request token is no longer needed
			$this->session->delete($this->key('request'));
			
			try
			{
				$data = array(
					'user_data' => $this->provider->user_data($token),
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

		// Add the callback URL to the consumer
		$this->client->callback($callback);

		// Redirect to the provider's login page
		$this->request->redirect($this->provider->authorize_url($this->client, array('scope' => $this->sso_config['scopes'])));
	}
	
}