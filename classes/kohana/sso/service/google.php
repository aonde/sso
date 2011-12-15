<?php defined('SYSPATH') or die('No direct script access.');

abstract class Kohana_SSO_Service_Google extends SSO_OAuth {
	
	/**
	 * @var  string  sso service name
	 */
	protected $sso_service = 'google';
	
}