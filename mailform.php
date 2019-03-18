<?php

session_start(); 

include("class.SecureMail.php");

$setup = new \security\forms\SecureMail();

$token = $setup->getToken();
$time  = $setup->setTime();

$_SESSION['token'] = $token;
	
	if(isset($_POST['token']))  {
		
		$finished_in_time = $setup->getTime();
		if($finished_in_time == TRUE) {
			
			if($_POST['token'] == $_SESSION['token']) {
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
					$token = $checkForm->getToken();
					} else {
					$checkForm->sessionmessage('Mail not sent.');
				}
			} else {
				$checkForm->sessionmessage('Invalid token.'); 
			}
		}
	// Show all session messages.
	$checkForm->showmessage();
	// Reset.
	$checkForm->clearmessages();
	}
	
?>

<h2>Secure mail form.</h2>
<p>Test form.</p>
<form action="" method="post">
<input type="hidden" name="token" value="<?php echo $token;?>">
			<label for="name">Name:</label><br>
				<input type="text" name="name" value="Jan Doe">
				<p><!-- message --></p>
			<label for="email">E-mail:</label><br>
				<input type="text" name="email" value="jane.doe@website.com">
				<p><!-- message --></p>
			<label for="subject">Subject:</label><br>			
				<input type="text" name="subject" value="Test">
				<p><!-- message --></p>
			<label for="body">Message:</label><br>
				<textarea name="body" rows="10" cols="40">Is it working? Hope so! -JD.</textarea>
				<p><!-- message --></p>
  <input type="submit" name="submit" value="Submit">
</form>
