<?php 

# This is the Glasnost load balancer

# Note: For test fetching, be aware that the webserver's firewall prohibits outgoing connections by default.

error_reporting(E_ALL | E_STRICT);
#error_reporting(E_ALL & ~E_NOTICE & ~E_USER_NOTICE); # Default w/o user notice


##############################################################################
# Do not change anything below this line unless you know what you are doing! #
##############################################################################

$server = array (
 				'http://loki08.mpi-sws.mpg.de/bb/',
				'http://loki09.mpi-sws.mpg.de/bb/',
				'http://loki10.mpi-sws.mpg.de/bb/'
);

# Global variables
$title = "Glasnost: Test if your ISP is shaping your traffic";
$subtitle = ""; # "<br><span style=\"font-size:10pt\" class=\"indent\">[beta]</span>"; #"<br><span style=\"font-size:10pt\" class=\"indent\">Powered by M-Lab</span>";


##########################
# Select a server to use #
##########################
function select_server() {
  global $server;
 
  return $server[mt_rand(0, (count($server))-1)];
}

##############################################
# Try to get a test from a different location 
##############################################
// Note: Only try to get the test from the servers that are used for uploads!
function find_test(){
	global $server;
		
	$id = $_GET['id'];
	if(!isset($id) || (preg_match("/^[\da-fA-F]+/",	$id) == 0)){
		header("HTTP/1.0 400 Bad Request");
		echo "Bad request.";
	}	
	$requester = $_SERVER['REMOTE_ADDR'];
	
	$server_list;
	for($i=0; $i<count($server); $i++){		
		# Get the IP address of the server
		$s = $server[$i];
		$p = strpos($s, "://");
		if($p){
			$s = substr($s, $p+3);
		}
		$p = strpos($s, "/");
		if($p){
			$s = substr($s, 0, $p);
		}

		$ip = gethostbyname($s); 
		
		if($ip != $requester){
			$server_list[] = $ip;
		}
	}
	
	$serialize = "";
	if(isset($_GET['serialize'])){
		$serialize = "&serialize=".$_GET['serialize'];
	}
	
	function myErrorHandler($errno, $errstr, $errfile, $errline){
		// $errstr contains a long error string that also contains the HTTP error, e.g., "HTTP/1.1 404 Not Found"
		//echo $errstr;
		return true;
	}
	
	for($i=0; $i<count(@$server_list); $i++){		
/* 		// Needs PECL extension which is not available (same for cUrl extension)		
  		$msg = http_parse_message(http_get("http://".$server_list[$i].":19981/?retrieve=script&id=$id"));
		if($msg->responseCode == 200){
			http_send_content_type('Content-type: text/plain');
			http_send_data($msg->body);
			exit(0);
		}
*/		
		$old_err = set_error_handler("myErrorHandler");
		$msg = file_get_contents("http://".$server_list[$i].":19981/?retrieve=script".$serialize."&id=$id");
		restore_error_handler();
		
		if($msg){
			header('Content-type: text/plain');
			echo $msg;		
			exit;
		}
	}
	
	header("HTTP/1.0 404 Not Found");
	echo "Not found.";
	exit;
}


#########################
# Redirect to startpage #
#########################
function redirect($next_page) {

	$params = "";
	
	# Check whether we redirect a GET or a POST request
	if(count($_POST) > 0){
		header("Location: $next_page");
		while($p = each($_POST)){
			header("$p[0]: $p[1]");
		}
				
	} else if(count($_GET) > 0){
		while($p = each($_GET)){
			$params = $params."$p[0]=$p[1]&";
		}
		header("Location: $next_page?$params");
	} else {	
		header("Location: $next_page");
	}

	exit;
}


function show_startpage(){
	
	global $title, $subtitle;
	
	$mserver = select_server() . "/glasnost.php";
	
	# Whether we should display an error message
	$error_code = 0;
	# Server was busy
	if(isset($_GET['busy'])){
		$error_code = 2;
	}
	
	$error = "";
	if($error_code == 2){
		$error = "<p style=\"border: 1px solid red;padding:5px;color:red;font-weight:bold;max-width:860px;\">We are sorry.
     Our measurement servers are currently overloaded and cannot serve you at the moment. Please try again later. 
     <br>
     </p>";

	}

	$warning = "";
	# Mac users have to run a signed applet
	if(stripos($_SERVER['HTTP_USER_AGENT'], "mac")){
		$warning = "<li  style=\"margin-left:-20px;\">
<b style=\"color:#69acff\">Note to MacOS X users:</b> To work around a unique policy setting in Apple's Java we had to sign our Java Applet for MacOS X. To run this test, you have to <i>\"trust\"</i> the applet in the popup window that will appear once you start the test.";
	}

	echo <<<END

	<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
	<html>
	  <head>
	    <title>$title</title>
	    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
	    <link rel="stylesheet" href="http://broadband.mpi-sws.org/mpi.css" type="text/css">
	    <link rel="shortcut icon" href="/favicon.ico" type="image/vnd.microsoft.icon">
	    <link rel="icon" href="/favicon.ico" type="image/vnd.microsoft.icon"> 
	
	    <style type="text/css">
	      a{ text-decoration: underline; }	
	    </style>
	    
	    <script type="text/javascript">
		    <!--
			function GenerateHelpText(testname) {      
				if(testname == "BitTorrent") {
					return 'Filesharing with BitTorrent.';
				} else if(testname == "HTTP") {
					return 'A file download from a webserver using HTTP.';
				} else if(testname == "IMAP") {
					return 'A download of an email with a large attachment from an IMAP email server.';
				} else if(testname == "POP") {
					return 'A download of an email with a large attachment from a POP email server.';
				} else if(testname == "FlashVideo") {
					return 'Flash video over HTTP, as used by, e.g., YouTube.';
				} else if(testname == "SSHTransfer") {
					return 'A file transfer over the SSH protocol, as done by the scp utility.';
				} else if(testname == "Gnutella") {
					return 'Filesharing with Gnutella.';
				} else if(testname == "eMule") {
					return 'Filesharing with eMule.';

				} else {
					return '<i>Sorry, no test description available.<\/i>';
				}
		    }

		    
			var IB=new Object;
			var posX=0;posY=0;
			var xOffset=10;yOffset=10;
			function ShowHelpbox(texte) {
				contenu="<div style=\"padding:2px;max-width:300px;background-color:"+IB.ColFond+";border: 1px solid "+IB.ColContour+";\"><span style=\"font-size:smaller;color:"+IB.ColTexte+";\">"+texte+"<\/span><\/div>&nbsp;";
				var finalPosX=posX-xOffset;
				if (finalPosX<0) finalPosX=0;
				if (document.layers) {
					document.layers["infoBox"].document.write(contenu);
				  	document.layers["infoBox"].document.close();
				  	document.layers["infoBox"].top=posY+yOffset;
				  	document.layers["infoBox"].left=finalPosX;
				  	document.layers["infoBox"].visibility="show";
				}
				if (document.all) {
				  	infoBox.innerHTML=contenu;
				  	document.all["infoBox"].style.top=posY+yOffset;
				  	document.all["infoBox"].style.left=finalPosX;
				  	document.all["infoBox"].style.visibility="visible";
				}		  
		  		else if (document.getElementById) {
					document.getElementById("infoBox").innerHTML=contenu;
					document.getElementById("infoBox").style.top=posY+yOffset;
					document.getElementById("infoBox").style.left=finalPosX;
					document.getElementById("infoBox").style.visibility="visible";
				}
			}
		  
			function getMousePos(e) {
				if (document.all) {
					posX=event.x+document.body.scrollLeft; 
					posY=event.y+document.body.scrollTop;
				} else {
					posX=e.pageX; 
					posY=e.pageY; 
				}
			}
			
		    function HideHelpBox() {
				if (document.layers) {document.layers["infoBox"].visibility="hide";}
				if (document.all) {document.all["infoBox"].style.visibility="hidden";}
				else if (document.getElementById){document.getElementById("infoBox").style.visibility="hidden";}
			}
		  
			function InitHelpBox(ColTexte,ColFond,ColContour) {
				IB.ColTexte=ColTexte;IB.ColFond=ColFond;IB.ColContour=ColContour;
				if (document.layers) {
					window.captureEvents(Event.MOUSEMOVE);window.onMouseMove=getMousePos;
					document.write("<layer name='infoBox' top=0 left=0 visibility='hide'><\/layer>");
				}
				if (document.all) {
					document.write("<div id='infoBox' style='position:absolute;top:0;left:0;padding:5px;visibility:hidden'><\/div>");
					document.onmousemove=getMousePos;
				} else if (document.getElementById) {
					document.onmousemove=getMousePos;
					document.write("<div id='infoBox' style='position:absolute;top:0;left:0;padding:5px;visibility:hidden'><\/div>");
				}		  
			}
		    
		  -->
		  </script>	    	   
		  
	  </head>
	
	
	  <body>
	    <a href="http://www.mpi-sws.mpg.de"><img src="http://broadband.mpi-sws.org/pics/mpisws-logo.png" alt="MPI-SWS" style="border:0px;background-color:white;vertical-align:bottom;"></a>
	    <h1 style="font-family:serif;">$title$subtitle</h1>
	
	
		<span style="border-top:1px solid #69acff;border-bottom:1px solid #69acff;font-weight:bold;">
		<img src="http://broadband.mpi-sws.org/pics/square.png" alt="*" style="margin-right:5px;margin-left:15px;margin-bottom:3px;">
		<a href="http://broadband.mpi-sws.org/transparency/" style="text-decoration:none">Home</a>
		<img src="http://broadband.mpi-sws.org/pics/square.png" alt="*" style="margin-right:15px;margin-left:5px;margin-bottom:3px;">
		<a href="http://broadband.mpi-sws.org/transparency/glasnost.php" style="text-decoration:none">Glasnost Tests</a>
		<img src="http://broadband.mpi-sws.org/pics/square.png" alt="*" style="margin-right:15px;margin-left:5px;margin-bottom:3px;">
		<a href="http://broadband.mpi-sws.org/transparency/glasnost.php?createtest" style="text-decoration:none">Create your own test</a>
		<img src="http://broadband.mpi-sws.org/pics/square.png" alt="*" style="margin-right:15px;margin-left:5px;margin-bottom:3px;">
		<a href="http://broadband.mpi-sws.org/transparency/code.html" style="text-decoration:none">Run your own server</a>
		<img src="http://broadband.mpi-sws.org/pics/square.png" alt="*" style="margin-right:15px;margin-left:5px;margin-bottom:3px;">
		<a href="http://broadband.mpi-sws.org/transparency/results/" style="text-decoration:none">Results</a>
		<img src="http://broadband.mpi-sws.org/pics/square.png" alt="*" style="margin-right:15px;margin-left:5px;margin-bottom:3px;">
		<a href="#contact" style="text-decoration:none">Contact</a>
		<img src="http://broadband.mpi-sws.org/pics/square.png" alt="*" style="margin-right:15px;margin-left:5px;margin-bottom:3px;">
		</span>
		<p>
	
	<div style="border:1px double #69acff;padding:15px;padding-bottom:5px;margin-bottom:10px;padding-top:10px;">
	
	  <div style="border-bottom:1px solid #c52b48;font-family:serif;font-weight:bold;color:#c52b48;">NEW!</div>
	    <ul class="bullet">
	    <li  style="margin-left:-20px;"><span style="color:#c52b48"><tt>04/08/10</tt></span>&nbsp;&nbsp;
	    <span style="font-weight:bold;">New Glasnost tests</span>:
	    We released 7 new Glasnost tests that complement our BitTorrent test. You can find and run them <a href="#tests">below</a>.
	    <li  style="margin-left:-20px;"><span style="color:#c52b48"><tt>03/21/10</tt></span>&nbsp;&nbsp;
	    Our paper describing Glasnost's design was accepted for publication at NSDI 2010.
	    <a href="http://broadband.mpi-sws.org/transparency/results/10_nsdi_glasnost.pdf">Read the paper here</a>.
	    </ul>
	</div>
	
	<div style="border:1px solid #69acff;padding:15px;">

	<p>The goal of the Glasnost project is to make ISPs' traffic shaping policies transparent to their customers.  
	   To this end, we designed Glasnost tests that enable you to check whether traffic from your applications is 
	   being rate-limited (i.e., throttled) or blocked.
	</p> 
	<p>Glasnost tests work by measuring and comparing the performance of different application flows between your
	   host and our measurement servers. The tests can detect traffic shaping in both upstream and downstream 
	   directions separately.  The tests can also detect whether application flows are shaped based on their port 
	   numbers or their packets' payload. For more details on how Glasnost tests work, please  
	   <!-- a href="http://broadband.mpi-sws.org/transparency/testdetails.html" target="_blank">this link</a>. -->
	   read our <a href="http://broadband.mpi-sws.org/transparency/results/10_nsdi_glasnost.pdf">NSDI 2010 paper</a>.
	</p>
	<p>We configured our tests to be conservative when declaring the presence of shaping, i.e., passing our tests 
	   does not necessarily mean that there is no throttling occurring on your link.
	</p>
    
    <script type="text/javascript">
	<!--
	InitHelpBox("#000000","#e8f2ff","#69acff");
	-->
	</script><a name="tests"></a>
    <form action="$mserver">

      <div style="border:1px solid #69acff;padding:15px;">

      <font style="border-bottom:1px solid #69acff;font-family:serif;font-weight:bold;">Select a Glasnost test to run</font>
             
      $error

        <input type="hidden" name="measure" value="yes"> 
		<input type="hidden" name="repeat" value="3">
		<input type="hidden" name="duration" value="20">
        <input type="hidden" name="down" value="yes">
        <input type="hidden" name="up" value="yes">
        <input type="hidden" name="port" value="0">
        <input type="hidden" name="port2" value="0">
                    
      
        <table style="margin-top:30px;" class="indent"><tr>
        <th style="vertical-align:top;border-bottom:1px dashed gray;">P2P apps</th>
        <th style="width:40px;">&nbsp;</th>
        <th style="vertical-align:top;border-bottom:1px dashed gray;">Standard apps</th>
        <th style="width:40px;">&nbsp;</th>
        <th style="vertical-align:top;border-bottom:1px dashed gray;">Video-on-Demand</th>
        </tr><tr>
        <td style="vertical-align:top;">
	        <span onMouseOver="ShowHelpbox(GenerateHelpText('BitTorrent'))" onMouseOut="HideHelpBox()"><input type="radio" name="protocol1" value="BitTorrent" checked> BitTorrent</span><br> 
	        <span onMouseOver="ShowHelpbox(GenerateHelpText('eMule'))" onMouseOut="HideHelpBox()"><input type="radio" name="protocol1" value="eMule"> eMule <span style="font-size:smaller;color:#c52b48;">[new]</span></span><br>
	        <span onMouseOver="ShowHelpbox(GenerateHelpText('Gnutella'))" onMouseOut="HideHelpBox()"><input type="radio" name="protocol1" value="Gnutella"> Gnutella <span style="font-size:smaller;color:#c52b48;">[new]</span></span><br>
        </td>
        <td>&nbsp;</td>
        <td style="vertical-align:top;">
        	<span onMouseOver="ShowHelpbox(GenerateHelpText('POP'))" onMouseOut="HideHelpBox()"><input type="radio" name="protocol1" value="POP"> Email (POP) <span style="font-size:smaller;color:#c52b48;">[new]</span></span><br>
        	<span onMouseOver="ShowHelpbox(GenerateHelpText('IMAP'))" onMouseOut="HideHelpBox()"><input type="radio" name="protocol1" value="IMAP"> Email (IMAP4) <span style="font-size:smaller;color:#c52b48;">[new]</span></span><br>
        	<span onMouseOver="ShowHelpbox(GenerateHelpText('HTTP'))" onMouseOut="HideHelpBox()"><input type="radio" name="protocol1" value="HTTP"> HTTP transfer <span style="font-size:smaller;color:#c52b48;">[new]</span></span><br>
        	<span onMouseOver="ShowHelpbox(GenerateHelpText('SSHTransfer'))" onMouseOut="HideHelpBox()"><input type="radio" name="protocol1" value="SSHTransfer"> SSH transfer <span style="font-size:smaller;color:#c52b48;">[new]</span></span><br>
        </td>
        <td>&nbsp;</td>
        <td style="vertical-align:top;">
        	<span onMouseOver="ShowHelpbox(GenerateHelpText('FlashVideo'))" onMouseOut="HideHelpBox()"><input type="radio" name="protocol1" value="FlashVideo"> Flash video (e.g., YouTube)<span style="font-size:smaller;color:#c52b48;">[new]</span></span><br>
        </td>
        </tr></table>
        <br>  
	   
       <ul class="bullet" style="margin-bottom:30px;line-height:150%;">
      
        <li style="margin-left:-20px;">Each Glasnost test takes approximately 8 minutes
        <li style="margin-left:-20px;"><span style="font-weight:bold">Note to all users:</span> 
        To allow accurate measurements you should stop any large downloads that might run in the background.
         
        $warning

      </ul>
        
      <p><input type="submit" value="&raquo; Start testing &laquo;" class="button"></p>
          
      </div>
    </form> 
    
	<table><tr><td style="padding-right:10px;vertical-align:top;">
	<a href="http://www.measurementlab.net" target="_top">
	<img src="http://broadband.mpi-sws.org/pics/mlab-logo.jpg" border="0" alt="M-Lab">
	</a>
	</td><td><i>
	Glasnost makes use of the <a href="http://www.measurementlab.net" target="_top">Measurement Lab</a> 
	(<a href="http://www.measurementlab.net" target="_top">M-Lab</a>) research platform.<br>
	To learn what information our tool collects, please go 
	<a href="http://www.measurementlab.net/measurement-lab-tools#glasnost">here</a>.</i>
	</td></tr></table>
END;

      if($error == ""){
      	
      	echo <<<END
    <p>&nbsp;</p><a name="contact"></a>
    <div style="border-bottom:1px solid #69acff;font-family:serif;font-weight:bold;">Who are we?</div>

    <p>We are researchers at the <a href="http://www.mpi-sws.org">Max Planck Institute for Software Systems</a>.
       Our research focuses on characterizing residential broadband networks and understanding their 
       implications for the designers of future protocols and applications.
       In case you have questions about this tool or our research, please visit our
       <a href="http://broadband.mpi-sws.org/transparency/">network transparency project webpage</a> or contact us via e-mail:
       <img src="http://broadband.mpi-sws.org/pics/email.png" alt="broadband @at@ mpi-sws mpg de" style="margin-left:5px;margin-bottom:-6px;">
    </p>

    <table class="indent">
    <tr>
     <th style="text-align:left;font-style:italic;color:#777777; width:300px;">Faculty</th>
     <th style="width:50px;">&nbsp;</th>
     <th style="text-align:left;font-style:italic;color:#777777; width:200px;">Students</th>
     <th style="width:50px;">&nbsp;</th>
     <th style="text-align:left;font-style:italic;color:#777777; width:400px;">Alumni</th>
    </tr>
    <tr>
      <td style="vertical-align:top;">
	<img src="http://broadband.mpi-sws.org/pics/square.png" alt="*" style="margin-right:5px;margin-bottom:3px;">
	<a href="http://www.mpi-sws.mpg.de/~gummadi/">Krishna P. Gummadi</a><br>
	<img src="http://broadband.mpi-sws.org/pics/square.png" alt="*" style="margin-right:5px;margin-bottom:3px;">
	<a href="http://research.microsoft.com/en-us/um/people/ratul/">Ratul Mahajan</a> (Microsoft Research)<br>
	<img src="http://broadband.mpi-sws.org/pics/square.png" alt="*" style="margin-right:5px;margin-bottom:3px;">
	<a href="http://research.microsoft.com/en-us/um/people/ssaroiu/">Stefan Saroiu</a> (Microsoft Research)<br>
      </td>
      <td style="width:50px;">&nbsp;</td>
      <td style="vertical-align:top">
	<img src="http://broadband.mpi-sws.org/pics/square.png" alt="*" style="margin-right:5px;margin-bottom:3px;">
	<a href="http://www.mpi-sws.org/~mdischin/">Marcel Dischinger</a><br>
	<img src="http://broadband.mpi-sws.org/pics/square.png" alt="*" style="margin-right:5px;margin-bottom:3px;">
	<a href="http://www.mpi-sws.org/~mmarcon/">Massimiliano Marcon</a><br>
      </td>
    <td style="width:50px;">&nbsp;</td>
    <td style="vertical-align:top;filter:alpha(opacity=60);-moz-opacity:0.6;-khtml-opacity: 0.6;opacity: 0.6;">
	<img src="http://broadband.mpi-sws.org/pics/square.png" alt="*" style="margin-right:5px;margin-bottom:3px;">
	<a href="http://www.mpi-sws.org/~sguha/">Saikat Guha</a> (Microsoft Research)<br>
	<img src="http://broadband.mpi-sws.org/pics/square.png" alt="*" style="margin-right:5px;margin-bottom:3px;">
	<a href="http://www.cis.upenn.edu/~ahae/">Andreas Haeberlen</a> (University of Pennsylvania)<br>
	<img src="http://broadband.mpi-sws.org/pics/square.png" alt="*" style="margin-right:5px;margin-bottom:3px;">
	<a href="http://www.ccs.neu.edu/~amislove">Alan Mislove</a> (North Eastern University)<br>
      </td>
    </tr>
    </table>
END;

      }
      else{
      	
      	echo <<<END
      <p><a name="contact"></a>
       In case you have questions about this tool or our research, please visit our
       <a href="http://broadband.mpi-sws.org/transparency/">network transparency project webpage</a> or contact us via e-mail:
       <img src="http://broadband.mpi-sws.org/pics/email.png" alt="broadband @at@ mpi-sws mpg de" style="margin-left:5px;margin-bottom:-6px;">
      </p>
END;

      }

      echo <<<END
	  </div>
	
	<script type="text/javascript">
	var gaJsHost = (("https:" == document.location.protocol) ? "https://ssl." : "http://www.");
	document.write(unescape("%3Cscript src='" + gaJsHost + "google-analytics.com/ga.js' type='text/javascript'%3E%3C/script%3E"));
	</script>
	<script type="text/javascript">
	var pageTracker = _gat._getTracker("UA-5410825-7");
	pageTracker._trackPageview();
	</script>
	
	  </body>
	</html>
END;

}

if(isset($_GET['busy']) && ($_GET['busy'] == 1)){
	show_startpage();
}
# submit-test.php
elseif((isset($_POST['script'])) || (isset($_GET['writescript'])) || (isset($_GET['writetest'])) || (isset($_FILES['scriptfile']))
|| (isset($_GET['retrieve'])) || (isset($_POST['retrieve'])) || (isset($_GET['createtest']))
){
	redirect(select_server()."/submit-test.php");
}
# glasnost.php
elseif((isset($_GET['measure'])) || (isset($_GET['done'])) || (isset($_POST['done'])) || (isset($_GET['error']))){
	redirect(select_server()."/glasnost.php");
}
elseif(isset($_GET['findtest']) && isset($_GET['id'])){
	find_test();
}
elseif((isset($_GET['alltests']))){
	$param = "$server[0]";
	for($i=1; $i<count($server); $i++){
		$param .= ";$server[$i]";
	}	
	$_GET['server'] = $param;
	redirect(select_server()."submit-test.php");
}

show_startpage();

?>
