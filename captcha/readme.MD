
# Captcha

Standalone Captcha which does not require the class. 

![Image of Captcha](https://raw.githubusercontent.com/flaneurette/class.SecureMail/56c2a651f9bb6ef1b62d1def915772559ca4dbd8/captcha/example.png)

The captcha image does not require the class. By default it does not show a captcha. To enable the use of a captcha, some additional code is required:

	// Setup new secure mail form.
	$setup = new \security\forms\SecureMail();
	
	// Try to detect a Robot on this form. If found, do you want to show a Captcha?
	$robot = $setup->detectrobot();

	if($robot == TRUE) {
		// CAPTCHA CODE HERE.
		echo "Prove to us you are not a robot.";
		echo '<img src="http://yourwebsite.tld/captcha/" width="120">';
		echo '<input type="text" name="captcha" value="">';
	}
	
Then, on the mailform.php you need to read the $_SESSION['captcha_question'] , which was stored inside the image session.

Like so:

	if($_SESSION['captcha_question'] === $_POST['captcha']) {
		echo "Captcha was correct!";
	}
	
And then decide what to do next...
