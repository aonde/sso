<?php defined('SYSPATH') or die('No direct script access.');

abstract class Kohana_SSO_Service_Gmail extends SSO_OAuth2 {
	
	/**
	 * @var  string  sso service name
	 */
	protected $sso_service = 'gmail';
	
}