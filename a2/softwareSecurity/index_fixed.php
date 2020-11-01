<?
session_start();

###################################################################################################
# https://www.owasp.org/index.php/Top_10_2013-Top_10
###################################################################################################
function sanitize_input($string, $isUserNameOrPassword)
{
    // maximum input length of 50 characters for username/password and 100 for expressions
    if ($isUserNameOrPassword)
    {
        $get_substring = substr($string, 0, 50);
        $pattern = "/<|>|{|}|&|\/|\\\|\\$/";
        $replacement = "";
        $cleaned_string = preg_replace($pattern, $replacement, $get_substring);
        return $cleaned_string;
    }
    else
    {
        $get_substring = substr($string, 0, 200);
        $pattern = "/((sqrt)*[\^+*4\-()\/]+)+$/";
        return preg_match($pattern, $get_substring);
    }
}

###################################################################################################
# FIX OWASP A8: CSRF (Cross Site Request Forgery)
# First verify that this is vulnerable. That is, if attacker gets target to follow a malicious
# URL, the attacker can get the user to perform an operation they had not intended.
# For example, craft a URL that gets the target to delete one of their entries.
# Fix this by creating a random page token. The page token is placed in the
# session. Now every reply to a page, includes the page token, in the URL, as a hidden variable etc.
# Before processing a request, first verify the page token.
###################################################################################################
$check_token = True;
// check if post token is set, and token in cookie is set, if so, check if they are equal
if (isset($_GET['token']) && !empty($_GET['token']) && isset($_SESSION['token']) && !empty($_SESSION['token']))
{
    if ($_GET['token'] == $_SESSION['token'])
    {
        $check_token = True;
    }
    else
    {
        $check_token = False;
    }
}

// Set new token on new request
$token = md5(uniqid(rand() , true));
$_SESSION['token'] = $token;

// make url to be used in the <form
$url_with_token = "http://192.168.10.100/fourFours/index.php?token=" . $token;

if (!isset($_SESSION['isLoggedIn'])) $_SESSION['isLoggedIn'] = False;
$operation = sanitize_input($_REQUEST['operation'], True);
$g_debug = "";
$g_errors = "";

// overridden database functions
function pg_connect_db()
{

    ###################################################################################################
    # FIX OWASP A6: SENSITIVE DATA EXPOSURE
    # Take a look at the db, whats wrong with the passwords?
    # Fix by hashing passwords, as well, you need to fix authentication to check hashes
    # Additionally, the application is not using https to communicate, fix this
    ###################################################################################################
    $dbconn = pg_connect("dbname=fourfours user=ff host=localhost password=adg135sfh246");
    pg_set_client_encoding($dbconn, 'UTF8');
    return $dbconn;
}

// only continue on if tokens are the same
if ($check_token)
{
    if ($operation == "login")
    {
        // sanitize inputs
        $user = sanitize_input($_POST['user'], True);
        $password = sanitize_input($_POST['password'], True);
        $dbconn = pg_connect_db();

        # A6 fix, using hashing sha256
        // get salt from database
        $query = "SELECT salt from account where username=$1";
        $stmtname = "get_salt";
        $result = pg_prepare($dbconn, $stmtname, $query);
        $result = pg_execute($dbconn, $stmtname, array(
            $user
        ));

        // hash using hash( hash(salt) + password )
        $username_found = False;
        $hashed_password="";
        if ($row = pg_fetch_row($result))
        {
            $salt = $row[0];
            $username_found = True;
            $hashed_password = hash("sha256", hash("sha256", $salt) . $password);
        }

        if ($username_found)
        {
            # FIX OWASP 2013 A1: SQL Injection, use prepared statements
            $query = "SELECT id, username, firstName, lastName, passwd FROM account WHERE username=$1 AND passwd='$hashed_password'";
            $stmtname = "find_user";
            $result = pg_prepare($dbconn, $stmtname, $query);
            $result = pg_execute($dbconn, $stmtname, array(
                $user
            ));
            if ($row = pg_fetch_row($result))
            {

                ###################################################################################################
                # FIX OWASP 2013 A2: SESSION FIXATION
                # Check that this application is vulnerable by bringing up firefox developer tools,
                # visiting the website, then logging in, notice that the same cookie is used after
                # change of privilege.
                # Fix this by...
                # Destroy current session and get a new session id when change in privilege.
                # Check to make sure that the cookie changes when logged in
                # Note: Some browsers now protect against reflection attacks, but not all.
                # See: http://php.net/manual/en/function.session-regenerate-id.php
                ###################################################################################################
                $_SESSION['accountId'] = $row[0];
                $_SESSION['user'] = $row[1];
                $_SESSION['firstName'] = $row[2];
                $_SESSION['lastName'] = $row[3];
                $_SESSION['isLoggedIn'] = True;

                session_regenerate_id(True);
            }
            else
            {
                $g_debug = "$user not logged in";
                $_SESSION['isLoggedIn'] = False;
            }

        }
        else
        {
            $g_debug = "$user not logged in";
            $_SESSION['isLoggedIn'] = False;
        }
    }
    elseif ($operation == "deleteExpression")
    {
        $expressionId = sanitize_input($_REQUEST['expressionId'], True);
        $accountId = sanitize_input($_REQUEST['accountId'], True);
        $dbconn = pg_connect_db();

        ###################################################################################################
        # FIX OWASP 2013 A4: INSECURE DIRECT OBJECT REFERENCES
        # Prove that it is vulnerable by logging in as one user and deleting another users entry
        # Fix this by...
        # Either fix the insecure part, that is, verify that the user can perform the operation
        # of the direct object reference part, that is, fix the id's so they don't directly
        # reference the expressionId, or both (even better).
        # Another problem: why get account id from the request? In this case, this is part of the
        # insecure direct object reference, that is, referencing the account id.
        # Note: Simply not giving the user interface the option to delete is not sufficient.
        ###################################################################################################
        $stmtname = "delete_expression";
        if ($accountId != $_SESSION['accountId'])
        {
            $g_errors = "ERROR: You cannot delete this Expression";
        }
        else
        {
            $result = pg_prepare($dbconn, $stmtname, "DELETE FROM solution WHERE id=$1 AND accountId=$2");
            $result = pg_execute($dbconn, $stmtname, array(
                $expressionId,
                $accountId
            ));
        }
    }
    elseif ($operation == "addExpression")
    {

        ###################################################################################################
        # FIX: XSS: user input/output is not vetted
        # First check that the application is vulnerable by placing html in the
        # database and then viewing the HTML as it exits the db
        # Fix this by ...
        # Either whitelisting the input, or escape the input
        # Do the same for all untrusted input and output!
        # http://stackoverflow.com/questions/46483/htmlentities-vs-htmlspecialchars
        ###################################################################################################
        $expression = "";
        $valid_expression = True;
        if (sanitize_input($_POST['expression'], False))
        {

            // max length it can be is 200 so we don't mess up the ui for other users
            $expression = substr($_POST['expression'], 0, 200);
        }
        else
        {
            $g_errors = "not a valid expression";
            $valid_expression = False;
        }

        if ($valid_expression)
        {
            $value = $_POST['value'];
            $accountId = $_POST['accountId'];

            $dbconn = pg_connect_db();
            $stmtname = "find_expression";
            $result = pg_prepare($dbconn, $stmtname, "SELECT * FROM solution WHERE expression=$1");
            $result = pg_execute($dbconn, $stmtname, array(
                $expression
            ));
            if (!($row = pg_fetch_row($result)))
            {
                $id = rand(0,10000000);
                // check if id exists already (unlikely)
                $stmtname="check_solution_id";
                $result = pg_prepare($dbconn, $stmtname, "SELECT * FROM solution WHERE id=$id");
                $result = pg_execute($dbconn, $stmtname, array());
                // keep making new id's until you make one that doesn't exist
                $count=0;
                while($row = pg_fetch_row($result)){
                  $id = rand(0,10000000);
                  $result = pg_prepare($dbconn, $stmtname . $count, "SELECT * FROM solution WHERE id=$id");
                  $result = pg_execute($dbconn, $stmtname . $count, array());
                  $count = $count + 1;
                }
                // generate new solution with a new id
                $stmtname = "add_expression";
                $result = pg_prepare($dbconn, $stmtname, "INSERT into solution (value, expression, accountId, id) values ($1, $2, $3, $4)");
                $result = pg_execute($dbconn, $stmtname, array(
                    $value,
                    $expression,
                    $accountId,
                    $id
                ));
            }
            else
            {
                $g_errors = "$expression is already in our database";
            }
        }

    }
    elseif ($operation == "logout")
    {
        unset($_SESSION);
        $_SESSION['isLoggedIn'] = False;
        session_regenerate_id(True);
    }
} else {
    if ($operation == "logout") {
        unset($_SESSION);
        $_SESSION['isLoggedIn'] = False;
        session_regenerate_id(True);
    }
}

$g_isLoggedIn = $_SESSION['isLoggedIn'];
$g_index = "";
for ($i = 0;$i <= 100;$i += 10)
{
    $g_index = $g_index . "<a href=#$i>$i</a> ";
}
$g_userFullName = $_SESSION['firstName'] . " " . $_SESSION['lastName'];
$g_userFirstName = $_SESSION['firstName'];
$g_accountId = $_SESSION['accountId'];
?>
<html>
	<body>
		<center>
		<h1>Four Fours</h1>
		<font color="red"><?=$g_errors ?></font><br/><br/>
    <? if(!$check_token && $g_isLoggedIn) { ?>
      <font color="red">CHECK TOKEN FAILED, - Cross-Site Request Forgery Attack Or just a refresh</font><br/><br/>
    <?}?>
		<? if($g_isLoggedIn){
			echo "<a href=?token=" . $token . "&operation=logout>Logout</a>"; ?>
			<br/>
			<br/>
			<div style="width:400px; text-align:left;">
			Welcome <?= $g_userFirstName ?>.
			Using only four 4s' and the operations +,-,*,/,^ (=exponentiation) and sqrt (=square root)
			create as many of the values below as you can. For example, for 2, I have ((4/4)+(4/4)), for 16, I have sqrt(4*4*4*4).
			</div>
			<br/>
			<table>
				<tr>
					<th>value</th><th>expression and author</th>
				</tr>
				<?php
				for($i=0;$i<=100;$i++){
					if($i%10==0){ ?>
						<td align="center" colspan="2" style="border-bottom:2pt solid black;"><?=$g_index ?></td>
					<? } ?>

					<tr>
						<td valign="top" style="border-bottom:2pt solid black;"> <a name="<?=$i?>" ><?=$i ?></a></td>
						<td valign="top" style="border-bottom:2pt solid black;">
							<table>
								<?php
									$dbconn = pg_connect_db();
									$result = pg_prepare($dbconn, "", "SELECT firstName, lastName, value, expression, s.accountId, s.id FROM account a, solution s WHERE a.id=s.accountId AND value=$i ORDER BY firstName, lastName, expression");
									$result = pg_execute($dbconn, "", array());
									# FIX XSS: Output from users must be whitelisted or escaped

									while ($row = pg_fetch_row($result)) {
										$count=0;
										$firstName=$row[$count++];
										$lastName=$row[$count++];
										$value=$row[$count++];
										$expression=$row[$count++];
										$expressionAccountId=$row[$count++];
										$expressionId=$row[$count++];
										if($expressionAccountId==$g_accountId){
											$deleteLink="<a href=\"?token=$token&operation=deleteExpression&expressionId=$expressionId&accountId=$g_accountId\"><img src=\"delete.png\" width=\"20\" border=\"0\" /></a>";
										} else {
											$deleteLink="";
										}
										echo("<tr> <td>$expression</td><td>$deleteLink</td><td>$firstName $lastName</td></tr>");
									}
								?>
								<tr>
									<form method="post" action="<?=$url_with_token?>">
										<td><input type="text" name="expression"/> </td>
										<td><input type="submit" value="add"/></td>
										<input type="hidden" name="value" value="<?=$i?>"/>
										<input type="hidden" name="operation" value="addExpression"/>
										<input type="hidden" name="accountId" value="<?=$g_accountId ?>"/>
									</form>
								</tr>
							</table>
						</td>
					</tr>
				<? } ?>
			</table>
		<? } else { ?>
			<form method="post" action="<?=$url_with_token?>">
				<table>
					<tr>
						<td>user name: <input type="text" size="10" name="user"/></td>
						<td>password: <input type="password" size="10" name="password"/> </td>
						<td>
							<input type="hidden" name="operation" value="login"/>
							<input type="submit" value="login"/>
						</td>
					</tr>
					<tr>
						<td colspan="3"><?php echo($g_debug); ?></td>
					</tr>
				</table>
			</form>
		<? } ?>
		</center>
	</body>
</html>
