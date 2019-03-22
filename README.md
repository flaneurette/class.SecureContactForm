# class.SecureMail

A Secure mail class and contact form for PHP. See the mailform.php for a complete example.

Since the beginning of the internet, securing a contact-form has been a notoriously difficult theme with regards to webapplication security. This class aims at tackling it in a practical and easy to understand way. The class uses the php internal mail function, a sendmail/qmail extension is planned. This class is particuarly useful for students who like to know more about webapplication security and see how certain challenges are approached. 

# Methodology:

The chain of security is called "Code Flow Chain" (CFC), it is a conditional flowing chain which follows a set of strict rules and quickly returns on the least expensive condition, as it flows back from the strongest to the weakest link in that chain. A simple flow chain can be such: Detect the strongest attack first, then Exit & Report. For example: We might consider that a brute force attack (automation) is the strongest attack, and so we focus on that chain first before we do anything else like handling user data, which then can overflow.

The Code Flow Chain of securing an application is as follows, albeit, in a very simplified way:

1. Create a tight secure environment or container: Initiate a unique session, set a secure cookie and additional security headers. 
2. Prevent CSRF: generate and set a unique secure token by generating pseudo random bytes. 
	1. On submitting the form, first check if the token was received and compare it against the session token.
	if these are both invalid, exit script or return false.
3. Prevent overflow: 
	1. Check the length of user-input. If too large, exit script or return false. Do nothing else.
4. Prevent injection: 
	1. All user and server supplied variables must be checked first in this chain-link.
	2. Avoid most PHP functions, avoid RegExing. Stick to tight functions like: stristr() to find a char. 
	3. Check for certain characters we wish to detect. Do not replace them, as this can lead to RegEx exploiting. 
	Instead, we detect and if we find an illegal character, exit script or return false. 
	4. Create a secure loop, check the array size first and cast the array to it's keys and values.
5. Prevent automation:
	1. Allocate a session with a number slots. (This can be done anywhere in the script.)
	2. Use a timer to measure how much time a user or bot spent on the form, if too short we assume it is automated. 
	We use the strength of bots -which is automation and impatience- against itself. It is rather expensive for a bot 
	to wait 10 seconds on each form.
6. Sanitizing data:
	0. If the chain is unbroken at this step, we can proceeded sanitizing user (and server) supplied data.
	1. Try not to be too clever: if we are here, we already know that most characters we look for were detected in step 4.
	2. Avoid most PHP functions, avoid RegExing. Stick to tight and low functions: htmlspcialchars, htmlentities or str_replace()
		1. Preference: Encode it. (htmlspecialchars, htmlentities)
		2. Alternative: Remove certain characters: str_ireplace(). Again, try not be too clever. Do not replace tags or 			markup, as it leads to injection. Instead, encode it so that it cannot not be either interpreted or rendered.
7. Logging and handling.
	1. Avoid printing verbatim user supplied data. Walk through this chain again.
	2. Logging and reporting can be part of the chain. We log, report and use this data to strengthen our chain.
	

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
