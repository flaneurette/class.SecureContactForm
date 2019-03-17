# class.SecureMail

A Secure mail class and contact form for PHP. See the mailform.php for a complete example.

# Simple implementation:

    include("class.SecureMail.php");

		$parameters = array( 
			'to' => 'info@yourwebsite.com',
			'name' => $_POST['name'],
			'email' => $_POST['email'],			
			'subject' => $_POST['subject'],
			'body' => $_POST['body']
		);
			
		$checkForm = new \security\forms\SecureMail($parameters);
		$scan = $checkForm->fullScan(); 
			
		if($scan != FALSE) {
			$checkForm->sendmail();
			$checkForm->sessionmessage('Mail sent!'); 
			} else {
			$checkForm->sessionmessage('Mail not sent.');
		}
