<?php
namespace security\forms;
###########################################################################
##                                                                       ##
##  Copyright 2008-2019 Alexandra van den Heetkamp.                      ##
##                                                                       ##
##  Secure Mail Class. This class processes e-mails coming from a        ##
##  contact form.                                                        ##
##                                                                       ##
##  This class is free software: you can redistribute it and/or modify it##
##  under the terms of the GNU General Public License as published       ##
##  by the Free Software Foundation, either version 3 of the             ##
##  License, or any later version.                                       ##
##                                                                       ##
##  This class is distributed in the hope that it will be useful, but    ##
##  WITHOUT ANY WARRANTY; without even the implied warranty of           ##
##  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        ##
##  GNU General Public License for more details.                         ##
##  <http://www.gnu.org/licenses/>.                                      ##
##                                                                       ##
###########################################################################
class SecureMail
{
	### CONFIGURATION 
	const MAXBODYSIZE 		= 5000; // number of chars of body text.
	const MAXFIELDSIZE 		= 50;   // number of allowed chars for single fields.
	
	const SERVERADDR		= 'server <server@localhost>'; 
	const DEFAULTTO			= 'postmaster@localhost'; // default "to" e-mail address when address has not been provided.
	const XMAILER			= 'Secure Mail';
	const MIMEVERSION		= '1.0';
	const TRANSFERENCODING 		= '8Bit';
	const CHARSET 			= 'UTF-8';
	const MAILFORMAT		= 'Flowed';  // Fixed, Flowed. (rfc3676)
	const DELSP			= 'Yes'; // Yes, No. (rfc3676)
	const OPTPARAM			= '-f'; // optional 5th parameter.
	const SUPRESSMAILERROR  	= true; // prevents PHP mail errors. (recommended)
	
	private $sieve 			= 0;    // Empty sieve 
	private $slots 			= 10;    // Maximum number of mail slots per user, per browse session. Increase for testing purposes.                      
	### END OF CONFIGURATION 
	
	public function __construct($params = array()) 
	{ 
		$this->init($params);
		$this->allocateMailSlots();
	}
	public function __destruct()
	{
		$this->bodyvectors = array();
		$this->fieldvectors = array();
	}
	public function fullScan() 
	{
		$this->allocateMailSlots();
		$this->fieldScan();
		$this->bodyScan();

		if($this->sieve >= 1) { 
			$this->sessionmessage('Mail sieve found issues within the form fields. Mail has not been sent!'); 
			return FALSE; // e-mail cannot be send.
			} else {
			return TRUE;
		}
	}
	
	/**
	* @var array form parameters.
	*/	
	public $fields = array();
	
	/**
	* Initializes object.
	* @param array $params
	* @throws Exception
	*/	
        public function init($params=[])
        {
		try {
			isset($params['to'])         ? $this->fields['to']  = $params['to'] : self::DEFAULTTO; 
			isset($params['name'])       ? $this->fields['name']   = $params['name'] : ''; 
			isset($params['email'])      ? $this->fields['email']    = $params['email']  : '';
			isset($params['url'])        ? $this->fields['url']    = $params['url']  : ''; 
			isset($params['phone'])      ? $this->fields['phone']    = $params['phone']  : '';
			isset($params['address'])    ? $this->fields['address']    = $params['address']  : '';	
			isset($params['city'])       ? $this->fields['city']    = $params['city']  : '';
			isset($params['country'])    ? $this->fields['country']    = $params['country']  : '';				
			isset($params['subject'])    ? $this->fields['subject']   = $params['subject'] : '';
			isset($params['terms'])      ? $this->fields['terms']   = $params['terms'] : '';
			isset($params['captcha'])    ? $this->fields['captcha']   = $params['captcha'] : '';
			isset($params['extrafield']) ? $this->fields['extrafield']   = $params['extrafield'] : '';
			isset($params['body'])       ? $this->fields['body'] = $params['body'] : false;
		} catch(Exception $e) {
			$this->sessionmessage('Problem initializing:'.$e->getMessage());
		}
         }
	/**
	* Occurence of these field vectors is allowed only once.
	* @var array
	*/	
	public $fieldvectors = array('@','+','-');
	
	/**
	* Disallowed body vectors, to prevent spam. 
	* (All html will be stripped on sending.)
	* @var array
	*/
	public $bodyvectors = array(
		'Return-Path','Content-Type','text/plain','MIME-Version','Content-Transfer-Encoding','Subject:','bcc:','<?php','<?'
	);
	
	/**
	* Disallowed characters. Only for detection (and logging) purposes.
	* @var array
	*/	
	public $disallowedchars = array(
		'%0A','%0D','\u000A','\u000D','0x000d','0x000a','&#13;','&#10;','\r','\n',
		';','<','>','`','~','$','%','/','\\','{','}','[',']','\'','"','=','-=','=-',
		'<?','?>','<%','%>','!#','<<<','-C ','-O ','../','./'
	);
	
	/**
	* Performs a scan on the field contents.
	* @return boolean
	*/	
	public function fieldScan() 
	{	
		foreach($this->fields as $key => $value)  {
		
				// check fieldsize.
				if(strlen($value) > self::MAXFIELDSIZE) { 
					$this->sessionmessage('Issue found: length of characters inside field exceed the maximum of ' . self::MAXFIELDSIZE); 
					$this->sieve++; 
				} 
				
				// check for disallowed chars
				for($j=0; $j<count($this->disallowedchars); $j++) { 
					if(stristr($value,$this->disallowedchars[$j])) {	
					$this->sessionmessage('Issue found: disallowed characters.'); 
					$this->sieve++;  
					}	
				}
				// scan for duplicate characters.
				for($k=0; $k<count($this->fieldvectors); $k++) {
					if(substr_count($value, $this->fieldvectors[$k]) >1) { 
						$this->sessionmessage('Issue found: duplicate characters.'); 
						$this->sieve++; 
					} 
				}
		}
		
		if($this->sieve >= 1) { 
			$this->sessionmessage('Mail sieve found issues within the form fields. Mail has not been sent!'); 
			return FALSE; // e-mail cannot be send.
			} else {
			return TRUE;
		}
	}
	
	/**
	* Performs a scan on the mail contents, and compares vectors that should not be present in the body text.
	* @return boolean
	*/	
	public function bodyScan() 
	{	
		if($this->fields['body'] != false) {
			for($i=0; $i<count($this->bodyvectors); $i++) {
				if(stristr($this->fields['body'], $this->bodyvectors[$i])) { 
					$this->sessionmessage('Issue found: body text contains disallowed characters.'); 
					$this->sieve++; 
				}
			}
		} else {
			$this->sessionmessage('Issue: body cannot be empty. Mail has not been sent!'); 
			$this->sieve++; 
		}
		
		if(strlen($this->fields['body']) > self::MAXBODYSIZE) {
			$this->sessionmessage('Issue: Maximum body text exceeded:' . self::MAXBODYSIZE); 
			$this->sieve++; 		
		}
		
		if($this->sieve >= 1) { 
			$this->sessionmessage('Mail sieve found issues within the form fields. Mail has not been sent!'); 
			return FALSE; // e-mail cannot be send.
			} else {
			return TRUE;
		}
	}
	/**
	* The main mail function.
	* @return mixed boolean.
	*/	
	public function sendmail() 
	{	
	
		$mime_headers = [];
		$from    = self::SERVERADDR; 		
		$to      = $this->clean($this->fields['to'],'field');
		$name    = $this->clean($this->fields['name'],'field');
		$subject = $this->clean($this->fields['subject'],'field');
		$message = $this->clean($this->fields['body'],'body');
		$ip      = $this->clean($_SERVER['REMOTE_ADDR'],'field');
	
		$headers = [
			'From'                      => self::SERVERADDR,
			'Sender'                    => self::SERVERADDR,
			'Return-Path'               => self::SERVERADDR,
			'MIME-Version'              => self::MIMEVERSION,
			'Content-Type'              => 'text/plain; charset='.self::CHARSET.'; format='.self::MAILFORMAT.'; delsp='.self::DELSP,
			'Content-Transfer-Encoding' => self::TRANSFERENCODING,
			'X-Mailer'                  => self::XMAILER,
		];
		
		foreach ($headers as $key => $value) {
			$mime_headers[] = "$key: $value";
		}
		$mail_headers = join("\n", $mime_headers);
		
		if(self::SUPRESSMAILERROR == true) {
			$send = @mail($to, $subject, $message, $mail_headers, self::OPTPARAM . $from);
			} else {
			$send = mail($to, $subject, $message, $mail_headers, self::OPTPARAM . $from);
		}
		return TRUE;
	}
 
 	/**
	* Allocates a pseudo random token to prevent CSRF.
	* @return mixed boolean, void.
	*/
	public function getToken()
	{
		$bytes  = mt_rand(0,0xfffffff) . mt_rand(0,0xfffffff) . mt_rand(0,0xfffffff);
		$bytes .= mt_rand(0,0xfffffff) . mt_rand(0,0xfffffff) . mt_rand(0,0xfffffff);
		$bytes .= mt_rand(0,0xfffffff) . bin2hex(random_bytes((256-(64 % 2)) / 2));
		$token = password_hash($bytes, PASSWORD_DEFAULT);
		
		if(isset($_SESSION['token'])) 
		{ 
			return $_SESSION['token']; 
			} else { 
			return $token;
		} 
	} 
  
	/**
	* Allocates the maximum mail slots.
	* @return mixed boolean, void.
	*/
	private function allocateMailSlots()
	{
		if(isset($_SESSION['current_mail_slot'])) 
		{ 
			if($_SESSION['current_mail_slot'] >= $this->slots) { 
				$this->sessionmessage('Mail slots exceeded. It is not allowed to send more than '.$this->slots.' per session.'); 
				return FALSE; 
				} else { 
				$_SESSION['current_mail_slot']++; 
			} 
		} else { 
			$_SESSION['current_mail_slot'] = 1; 
		} 
	}
	
	/**
	* Store session messages
        * @param string $value
	* @return void
	*/ 
	public function sessionmessage($value) 
	{ 
		if(isset($_SESSION['mail_message'])) { 
			array_push($_SESSION['mail_message'],$value);  
		} else { 
			$_SESSION['mail_message'] = array(); 
		} 
	} 
	/**
	* Dumps session messages
	* @return void
	*/	
	public function showmessage() 
	{ 
		if(!empty($_SESSION['mail_message'])) { 
			echo "<pre>"; 
			echo "<strong>Message:</strong>\r\n"; 
			foreach($_SESSION['mail_message'] as $message) { 
				echo $this->clean($message,'encode') . "\r\n" ; 
			} echo "</pre>"; 
		} 
	} 
	/**
	* Clears session messages
	* @return void
	*/	
	public function clearmessages() 
	{
		$_SESSION['mail_message'] = array(); 
	}
	
	/**
	* Checks e-mail address
	* @return mixed boolean
	*/
	public function checkAddress($string) 
	{
		// with all the new domain name extensions we allow a for maximum 14.
		if (preg_match('/^[A-Za-z0-9-_.+%]+@[A-Za-z0-9-.]+.[A-Za-z]{2,14}$/',$string)) {
			return TRUE;
			} else {
			return FALSE;
		}
	}
	
	/**
	* Cleans a string.
	* @return string
	*/		
	public function clean($string,$method) {
		
		$buffer=self::MAXFIELDSIZE;
		
		$data = '';
		switch($method) {
			case 'alpha':
				$this->data =  preg_replace('/[^a-zA-Z]/','', $string);
			break;
			case 'alphanum':
				$this->data =  preg_replace('/[^a-zA-Z-0-9]/','', $string);
			break;
			case 'field':
				$this->data =  preg_replace('/[^A-Za-z0-9-_.@]/','', $string);
			break;			
			case 'num':
				$this->data =  preg_replace('/[^0-9]/','', $string);
			break;
			case 'unicode':
				$this->data =  preg_replace("/[^[:alnum:][:space:]]/u", '', $string);
			break;
			case 'encode':
				$this->data =  htmlspecialchars($string,ENT_QUOTES,'UTF-8');
			break;
			case 'body':
				$this->data =  strip_tags($string);
			break;
			}
		return $this->data;
	}
}

?>
