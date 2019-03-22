# class.SecureMail

A Secure mail class and contact form for PHP. See the mailform.php for a complete example.

Since the beginning of the internet, securing a contact-form has been a notoriously difficult theme with regards to webapplication security. This class aims at tackling it in a practical and easy to understand way. The class uses the php internal mail function, a sendmail/qmail extension is planned. This class is particuarly useful for students who like to know more about webapplication security and see how certain challenges are approached. 


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
