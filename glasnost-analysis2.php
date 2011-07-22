<?php

# This implements the NSDI 2010 traffic differentiation algorithm
# Also detects TCP RST blocking and general blocking using packet dropping.

error_reporting(E_ALL | E_STRICT);

# Thresholds to determine whether there is rate limiting
$noise_thres = 0.2;
$diff_thres = 0.2;

define("UPLOAD", 0);
define("DOWNLOAD", 1);

###############################################
# Process test results and display a summary
###############################################

# This function makes assumptions about the test run (e.g., the order and what flows were run)
function get_differentiation_results($warn_msg = null, $download_logs = FALSE)
{
	global $title, $subtitle, $store_directory, $this_script;
	global $noise_thres, $diff_thres;

	if(isset($warn_msg) && ($warn_msg != "")){
		$warning[] = $warn_msg;
	}
	
	# Some general information
	$ts = time();   # Timestamp
	$hostip = $_SERVER['REMOTE_ADDR'];
	$hostname = "";
	$args = "";


	# Read in all parameters passed from the applet
	while($p = each($_GET))
	{
		if(($p[0] == "sysinfo") || ($p[0] == "exception") || ($p[0] == "server") ||
		($p[0] == "msg") || ($p[0] == "mid") || ($p[0] == "peer") || $p[0] == "internal"){}
		else{
			$args .= "$p[0]=$p[1]&";
		}

		if($p[0] == "done"){}
		elseif($p[0] == "internal"){}
		elseif($p[0] == "down"){}
		elseif($p[0] == "up"){}
		elseif($p[0] == "protocol1"){
			$protocol1 = $p[1];
		}
		elseif($p[0] == "protocol2"){
			$protocol2 = $p[1];
		}
		elseif($p[0] == "duration"){
			$duration = $p[1];
		}
		elseif($p[0] == "sysinfo"){}
		elseif($p[0] == "id"){
			if(is_numeric($p[1])){ $ts = $p[1]; }
		}
		elseif($p[0] == "server"){
			$server = $p[1];
		}
		elseif($p[0] == "peer"){
			$hostip = $p[1];
		}
		elseif($p[0] == "hostname"){
			$hostname = $p[1];
		}
		elseif($p[0] == "port"){
			$port1 = $p[1];
		}
		elseif($p[0] == "port2"){
			$port2 = $p[1];
		}
		elseif($p[0] == "repeat"){
			$repeat = $p[1];
		}


		# Now read what the client found
		elseif(preg_match('/^expu\d+/', $p[0])){
			$index = substr($p[0], 4); # Just give me the number at the end
			$expu[$index] = $p[1];
			if(! isset($expr[$index])){ $expr[$index] = 0; }
		}
		elseif(preg_match('/^expd\d+/', $p[0])){
			$index = substr($p[0], 4); # Just give me the number at the end
			$expd[$index] = $p[1];
			if(! isset($expr[$index])){ $expr[$index] = 0; }
		}
		elseif(preg_match('/^expl\d+/', $p[0])){
			$index = substr($p[0], 4); # Just give me the number at the end
			$expl[$index] = $p[1];
		}
		elseif(preg_match('/^expr\d+/', $p[0])){
			$index = substr($p[0], 4); # Just give me the number at the end
			$expr[$index] = $p[1];
		}
		elseif(preg_match('/^expstate\d+/', $p[0])){}
		elseif(preg_match('/^expp\d+/', $p[0])){
			$index = substr($p[0], 4); # Just give me the number at the end
			$port[$index] = $p[1];
		}
		elseif(preg_match('/^expprot\d+/', $p[0])){}
		elseif(preg_match('/^expserv\d+/', $p[0])){}

		# Server side
		elseif(preg_match('/^expsu\d+/', $p[0])){
			$index = substr($p[0], 5); # Just give me the number at the end
			$expsu[$index] = $p[1];
			if(! isset($expsr[$index])){ $expsr[$index] = 0; }
			if(! isset($expsrs[$index])){ $expsrs[$index] = 0; }
		}
		elseif(preg_match('/^expsd\d+/', $p[0])){
			$index = substr($p[0], 5); # Just give me the number at the end
			$expsd[$index] = $p[1];
			if(! isset($expsr[$index])){ $expsr[$index] = 0; }
			if(! isset($expsrs[$index])){ $expsrs[$index] = 0; }
		}
		elseif(preg_match('/^expsl\d+/', $p[0])){
			$index = substr($p[0], 5); # Just give me the number at the end
			$expsl[$index] = $p[1];
		}
		elseif(preg_match('/^expsr\d+/', $p[0])){
			$index = substr($p[0], 5); # Just give me the number at the end
			$expsr[$index] = $p[1];
		}
		elseif(preg_match('/^expsrs\d+/', $p[0])){
			$index = substr($p[0], 5); # Just give me the number at the end
			$expsrs[$index] = $p[1];
		}
		elseif(preg_match('/^expsstate\d+/', $p[0])){}

		# DEBUG ONLY
		else{
			echo "<p style=\"color:red\">DEBUG: Unknown Parameter: \"$p[0]=$p[1]\"</p>";
		}
	}

	if($hostname == ""){
		$hostname = gethostbyaddr($hostip);
	}

	if(! isset($repeat)){
		echo "<p style=\"color:red\">ERROR: Repeat parameter not set. Assuming 3, but this is likely to be wrong.</p>";
		$repeat = 3;
	}

	if(! isset($protocol2)){
		$protocol2 = "control flow";
	}

	# Sanity check for short tests
	if(1)
	{
		$avg_duration = 0;
		$num_exp = 0;
		for($i=0; $i<count($expu); $i++){
			if(($expu[$i] <= 0) && ($expd[$i] <= 0) && ($expsd[$i] <= 0) && ($expsu[$i] <= 0)){ next; }
			
			if(isset($expl[$i]) && isset($expsl[$i])){
				$avg_duration += max($expl[$i], $expsl[$i]);
				$num_exp++;
			}
			elseif(isset($expl[$i])){
				$avg_duration += $expl[$i];
				$num_exp++;
			}
			elseif(isset($expsl[$i])){
				$avg_duration += $expsl[$i];
				$num_exp++;
			}
		}
		if($num_exp > 5){
			$avg_duration /= $num_exp;
			
			if($avg_duration < MIN_TEST_DURATION){ # in seconds
				$warning[] = "<b>Warning:</b> The average duration of your test flows was only ".round($avg_duration,2)." seconds.  Measurements from short duration flows tend to be more noisy, which leads to less accurate results. We recommend that you configure the test flows to run for longer than ".MIN_TEST_DURATION." seconds.";
			}
		}
	}
	
	# Check ports used
	if($port1 <= 0){ # runs 0..(($repeat*2)-1), ($repeat*4)..(($repeat*6)-1)
		$port1_orig = $port1;
		$port1 = $port[0];
	}
	if($port2 <= 0){ # runs ($repeat*2)..($repeat*4)-1), ($repeat*6)..(($repeat*8)-1)
		$port2_orig = $port2;
		$port2 = $port[($repeat*2)];
	}

	$p = 0;
	for($i=0; $i<($repeat*2); $i++){
		$p += $port[$i];
	}
	for($i=($repeat*4); $i<($repeat*6); $i++){
		$p += $port[$i];
	}
	if($p != ($port[0]*($repeat*4))){
		$warning[] = "<b>Attention:</b> The first TCP port used ($port1) changed during the test. This was done at the measurement server as the port was occupied. Be aware that this can affect the correctness of the results.";
	}

	$p = 0;
	for($i=($repeat*2); $i<($repeat*4); $i++){
		$p += $port[$i];
	}
	for($i=($repeat*6); $i<($repeat*8); $i++){
		$p += $port[$i];
	}
	if($p != ($port[($repeat*2)]*($repeat*4))){
		$warning[] = "<b>Attention:</b> The second TCP port used ($port2) changed during the test. This was done at the measurement server as the port was occupied. Be aware that this can affect the correctness of the results.";
	}
	else{
		if($port[0] != $port1){
			$warning[] = "<b>Note:</b> The server changed the requested port $port1 to $port[0] as the original port was occupied.";
			$port1_orig = $port1;
			$port1 = $port[0];
		}
		if($port[($repeat*2)] != $port2){
			$warning[] = "<b>Note:</b> The server changed the requested port $port2 to ".$port[($repeat*2)]." as the original port was occupied.";
			$port2_orig = $port2;
			$port2 = $port[($repeat*2)];
		}
	}

	# Sanity checks

	$port1_failed = 0;
	$port2_failed = 0;

	# First-port runs
	$length_check = 0;
	for($i=0; $i<($repeat*2); $i++){
		$length_check += $expsl[$i];
		if($length_check > 0){ break; }
	}
	if($length_check == 0){
		for($i=($repeat*4); $i<($repeat*6); $i++){
			$length_check += $expsl[$i];
			if($length_check > 0){ break; }
		}
	}
	if($length_check == 0){
		$port1_failed = 1;
	}

	# Second-port runs
	$length_check = 0;
	for($i=($repeat*2); $i<($repeat*4); $i++){
		$length_check += $expsl[$i];
		if($length_check > 0){ break; }
	}
	if($length_check == 0){
		for($i=($repeat*6); $i<($repeat*8); $i++){
			$length_check += $expsl[$i];
			if($length_check > 0){ break; }
		}
	}
	if($length_check == 0){
		$port2_failed = 1;
	}

	# Get noise and max tput for each flow type
	####################

	# 0: protocol1 upstream port1
	# 1: protocol2 upstream port1
	# 2: protocol1 upstream port2
	# 3: protocol2 upstream port2
	# 4: protocol1 downstream port1
	# 5: protocol2 downstream port1
	# 6: protocol1 downstream port2
	# 7: protocol2 downstream port2


	$dir = array();
	$uncertainty = 0;
	# Decide which of the flows are uploads and which are downloads
	for($n=0; $n<2; $n++)
	{
		$up = 0; $down = 0;
		for($i=0; $i<$repeat*4; $i++)
		{
			if(isset($expd[$n*$repeat*4+$i]) && isset($expsd[$n*$repeat*4+$i]))
			{
				if($expd[$n*$repeat*4+$i] > $expsd[$n*$repeat*4+$i]) { $down++; }
				elseif($expd[$n*$repeat*4+$i] < $expsd[$n*$repeat*4+$i]) { $up++; }
				else # use default
				{
					if($n == 0){ $up++; }
					else { $down++; }
				}
			}
		}

		if($up > $down){ $dir[$n] = UPLOAD; }
		elseif($up < $down){ $dir[$n] = DOWNLOAD; }
		elseif($n == 0){ $dir[$n] = UPLOAD; }
		else { $dir[$n] = DOWNLOAD; }

		$uncertainty = max($uncertainty, 1/abs($up-$down));
	}
	
	if(($dir[0] == $dir[1]) || ($uncertainty > (1/$repeat)))
	{
		if(isset($_GET['internal']) && ($_GET['internal'] == 1)) # Fall back to defaults
		{
			$dir[0] = UPLOAD;
			$dir[1] = DOWNLOAD;
		}
		else
		{		
			# TODO Fall back to just display a table.
			echo "<p style=\"color:red;font-weight:bold;padding:10px;border:1px;\">Error: Direction detection failed. Cannot display results.</p>";
			get_detailed_results();
			return;
		}
	}

	
	# TMP store what we display
	ob_start();

	echo "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">
<html>
  <head>
    <title>$title</title>
    <meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">
    <link rel=\"stylesheet\" href=\"mpi.css\" type=\"text/css\">
    <link rel=\"shortcut icon\" href=\"./favicon.ico\" type=\"image/vnd.microsoft.icon\">
    <link rel=\"icon\" href=\"./favicon.ico\" type=\"image/vnd.microsoft.icon\"> 
    
    <style type=\"text/css\">
      th { border-bottom:1px solid black; padding:5px; padding-left: 10px; padding-right: 10px; }
      td { padding:5px; } 
    </style>
    
    
    
  </head>

  <body>
    <a href=\"http://www.mpi-sws.org\"><img src=\"pics/mpisws-logo.png\" alt=\"MPI-SWS\" style=\"border:0px;background-color:white;vertical-align:bottom;\"></a>
    <h1 style=\"font-family:serif;\">$title$subtitle</h1>

  <div style=\"width:75%;border:1px solid #69acff;padding:15px;\">
    
    <div style=\"border-bottom:1px solid #69acff;font-family:serif;font-weight:bold;\">
      Results for your host <i>($hostname - $hostip)</i>:</div>      
	";

	if(count(@$warning) > 0){
		echo "<p style=\"border:1px solid #ff7200; padding:10px; color: #ff7200;\">";
		for($i=0; $i<count($warning); $i++){
			if($i > 0){ echo "<br>"; }
			echo "$warning[$i]<br>\n";
		}
		echo "</p>";
	}
	
	$type_bpslist = array();
	$type_dir = array();

	$max = array();
	$noise = array();
	$blocking = array();
	$nodata = array();

	for($n=0; $n<8; $n++)
	{
		if($n == 0) { $base = 0; $port = $port1; }
		elseif($n == 1) { $base = 1; $port = $port1; }
		elseif($n == 2) { $base = 2*$repeat; $port = $port2; }
		elseif($n == 3) { $base = 2*$repeat+1; $port = $port2; }
		elseif($n == 4) { $base = 4*$repeat; $port = $port1; }
		elseif($n == 5) { $base = 4*$repeat+1; $port = $port1; }
		elseif($n == 6) { $base = 6*$repeat; $port = $port2; }
		elseif($n == 7) { $base = 6*$repeat+1; $port = $port2; }

		$bps = array(); # Reset
		$bps_list = "";
		$sane = 1;
		$reset_count = 0;
		$nodata_count = 0;
		
		
		for($i=0; $i<$repeat; $i++)
		{
			if((!isset($expl[$base+$i*2]) || !($expl[$base+$i*2] > 0)) &&
			   (!isset($expsl[$base+$i*2]) || !($expsl[$base+$i*2] > 0)))
			{
				$sane = 0;
				$nodata_count ++;
				//break;
			}
		}
		$nodata[$n] = $nodata_count;
		$blocking[$n] = 0;

		if($n < 4){ $direction = $dir[0]; }
		else { $direction = $dir[1]; }

		if($sane == 1)
		{
			# Quantify noise and get max
			for($i=0; $i<$repeat; $i++)
			{
				if($direction == DOWNLOAD)
				{
					if(isset($expd[$base+$i*2]) && ($expd[$base+$i*2] > 0))
					{
						$bps[] = sprintf("%d", (int)(0.008* $expd[$base+$i*2] / $expl[$base+$i*2]));
						$bps_list = sprintf("%s;%d", $bps_list, $bps[count($bps)-1]);
					}
					else
					{
						$nodata_count++;
						$bps_list = sprintf("%s;failed", $bps_list);
					}
				}
				elseif($direction == UPLOAD)
				{
					if(isset($expsd[$base+$i*2]) && ($expsd[$base+$i*2] > 0))
					{
						$bps[] = sprintf("%d", (int)(0.008* $expsd[$base+$i*2] / $expsl[$base+$i*2]));
						$bps_list = sprintf("%s;%d", $bps_list, $bps[count($bps)-1]);
					}
					else
					{
						$nodata_count++;
						$bps_list = sprintf("%s;failed", $bps_list);
					}
				}

				# Checking: If both sides have seen resets and the server did not send any
				if(isset($expsr[$base+$i*2]) && isset($expr[$base+$i*2]) && ($expr[$base+$i*2] > 0) && ($expsr[$base+$i*2] > 0) && ($expl[$base+$i*2] < $duration)
				&& (!isset($expsrs) || !isset($expsrs[$base+$i*2]) || ($expsrs[$base+$i*2] == 0)))
				{
					$reset_count++;
				}
			}
				
			$blocking[$n] = $reset_count;
			$nodata[$n] = $nodata_count;
				
			if(count($bps) > 0)
			{
				sort($bps, SORT_NUMERIC);

				$max[$n] = $bps[count($bps)-1];
				if(isset($bps[count($bps)-1]) && ($bps[count($bps)-1] > 0))
				{
					$noise[$n] = ($bps[count($bps)-1] - $bps[(int)(floor(0.5*count($bps)))]) / $bps[count($bps)-1];
				}
				$bps = array(); # Reset

				$type_bpslist[$n] = substr($bps_list, 1);
				$type_dir[$n] = $direction;
			}
		}
	}

	$title_printed = 0;

	if(($port1_failed + $port2_failed) > 0)
	{
		echo "<h3 class=\"indent\" style=\"color:#777777;\">Are certain ports blocked for all traffic?</h3>";
		$title_printed = 1;

		if($port1_failed == 1)
		{
			echo "<p class=\"indent\">
					<img src=\"pics/square.png\" alt=\"*\" style=\"margin-right:5px;margin-left:5px;margin-bottom:3px;\">
					<span style=\"color:red;font-weight:bold;\">Glasnost was unable to connect to the server port $port1.</span>
					It is likely that this port is blocked for all connections, e.g., by a traffic shaper or a local firewall.
				</p>";
		}
		if($port2_failed == 1)
		{
			echo "<p class=\"indent\">
					<img src=\"pics/square.png\" alt=\"*\" style=\"margin-right:5px;margin-left:5px;margin-bottom:3px;\">
					<span style=\"color:red;font-weight:bold;\">Glasnost was unable to connect to the server port $port2.</span>
					It is likely that this port is blocked for all connections, e.g., by a traffic shaper or a local firewall.
				</p>";
		}
	}


	# Display results
	####################

	# 1. Blocking (no data or TCP RST)

	for($n=0; $n<8; $n++)
	{
		# Exclude flows that we already reported to be blocked
		if(($n == 0) || ($n == 1) || ($n == 4) || ($n == 5)) {
			if($port1_failed == 1){	continue; }
			$port = $port1;
		}
		if(($n == 2) || ($n == 3) || ($n == 6) || ($n == 7)) {
			if($port2_failed == 1){ continue; }
			$port = $port2;
		}
			
		if($n < 4){ $direction = "upload"; }
		else { $direction = "download"; }

		if(($n%2) == 0){ $protocol = $protocol1; }
		else { $protocol = $protocol2; }

		if(($title_printed == 0) && (($blocking[$n] + $nodata[$n]) > 0))
		{
			echo "<h3 class=\"indent\" style=\"color:#777777;\">Are certain ports blocked for all traffic?</h3>";
			$title_printed = 1;
				
			# TODO echo "<p class=\"indent2\"><span style=\"color:red;font-weight:bold;\">Your ISP appears to block your ${direction}s.</span> $noise_warning</p>\n";
			# TODO Port-based vs app-based blocking?
		}

		if($blocking[$n] > 0)
		{
			echo "<p class=\"indent2\">
				<span style=\"color:red;font-weight:bold;\">$blocking[$n] out of $repeat $protocol transfers on port $port were
				interrupted while ${direction}ing using forged TCP RST packets.</span>
				It seems like your ISP hinders you from ${direction}ing $protocol traffic on port $port to our test server.
				</p>
				";
		}

		elseif($nodata[$n] > 0)
		{
			echo "<p class=\"indent2\">
				<span style=\"color:red;font-weight:bold;\">$nodata[$n] out of $repeat $protocol transfers on port $port 
				failed to $direction any data.</span>
				It seems like your ISP hinders you from ${direction}ing $protocol traffic on port $port to our test server.
				</p>
				";			
		}

		#echo "<p style=\"color:red;font-weight:bold;padding:10px;border:1px;\">DEBUG: $max[$n] $noise[$n] $type_dir[$n] $type_bpslist[$n]</p>";
	}

	# 2. Differentiating (NEW)
	define("NOISE", 0);
	define("YES", 1);
	define("NO", 2);
	for($n=0; $n<4; $n++)
	{
		# Start with upstream
		if(($n%2) == 0){ $direction = "upload"; }
		else { $direction = "download"; }
			
		$diff = 0;
		$noisy = 0;
			
		$max_cf = -1;
		$max_pr = -1;
			
		if(($n == 0) || ($n == 1)) # Application-based differentiation
		{
			if($n == 0) # Upstream
			{
				if($dir[0] == UPLOAD){ $base = 0; }
				else { $base = 4; }
			}
			elseif($n == 1) # Downstream
			{
				if($dir[0] == DOWNLOAD){ $base = 0; }
				else { $base = 4; }
			}

			$max1 = $max[$base];
			$max2 = $max[$base+1];
			$noise1 = $noise[$base];
			$noise2 = $noise[$base+1];

			if(($noise1 <= $noise_thres) && ($noise2 <= $noise_thres))
			{
				if((abs($max1 - $max2)/max($max1, $max2)) > $diff_thres)
				{
					$diff_res[$n] = YES;
					$diff_detail[$n][0] = $max2;
					$diff_detail[$n][1] = $max1;
				}
				else
				{
					$diff_res[$n] = NO;
					$diff_detail[$n][0] = $max2;
					$diff_detail[$n][1] = $max1;
				}
			}
			else { $diff_res[$n] = NOISE; }
				
				
			$max1 = $max[$base+2];
			$max2 = $max[$base+3];
			$noise1 = $noise[$base+2];
			$noise2 = $noise[$base+3];

			if(($noise1 <= $noise_thres) && ($noise2 <= $noise_thres))
			{
				if((abs($max1 - $max2)/max($max1, $max2)) > $diff_thres)
				{
					$diff_res[4+$n] = YES;
					$diff_detail[4+$n][0] = $max2;
					$diff_detail[4+$n][1] = $max1;
				}
				else
				{
					$diff_res[4+$n] = NO;
					$diff_detail[4+$n][0] = $max2;
					$diff_detail[4+$n][1] = $max1;
				}
			}
			else { $diff_res[4+$n] = NOISE; }
		}
		elseif(($n == 2 || $n == 3)) # Port-based differentiation
		{
			if($n == 2) # Upstream
			{
				if($dir[0] == UPLOAD){ $base = 0; }
				else { $base = 4; }
			}
			elseif($n == 3) # Downstream
			{
				if($dir[0] == DOWNLOAD){ $base = 0; }
				else { $base = 4; }
			}

			$max1 = $max[$base];
			$max2 = $max[$base+2];
			$noise1 = $noise[$base];
			$noise2 = $noise[$base+2];

			if(($noise1 <= $noise_thres) && ($noise2 <= $noise_thres))
			{
				if((abs($max1 - $max2)/max($max1, $max2)) > $diff_thres)
				{
					if($max1 > $max2) {	$diff_port = $port2; }
					else { $diff_port = $port1; }

					$diff_res[$n] = YES;
					$diff_detail[$n][0] = $max2;
					$diff_detail[$n][1] = $max1;
					$diff_detail[$n][2] = $diff_port;
				}
				else
				{
					$diff_res[$n] = NO;
					$diff_detail[$n][0] = $max2;
					$diff_detail[$n][1] = $max1;
				}
			}
			else { $diff_res[$n] = NOISE; }

			$max1 = $max[$base+1];
			$max2 = $max[$base+3];
			$noise1 = $noise[$base+1];
			$noise2 = $noise[$base+3];

			if(($noise1 <= $noise_thres) && ($noise2 <= $noise_thres))
			{
				if((abs($max1 - $max2)/max($max1, $max2)) > $diff_thres)
				{
					if($max1 > $max2) {	$diff_port = $port2; }
					else { $diff_port = $port1; }

					$diff_res[4+$n] = YES;
					$diff_detail[4+$n][0] = $max2;
					$diff_detail[4+$n][1] = $max1;
					$diff_detail[4+$n][2] = $diff_port;
				}
				else
				{
					$diff_res[4+$n] = NO;
					$diff_detail[4+$n][0] = $max2;
					$diff_detail[4+$n][1] = $max1;
				}
			}
			else { $diff_res[4+$n] = NOISE; }
				
		}
	}

	# Now output results
	for($n=0; $n<2; $n++)
	{
		# Start with upstream
		if(($n%2) == 0){ $direction = "upload"; }
		else { $direction = "download"; }

		# Is there differentiation in the upstream/downstream?
		echo "<h3 class=\"indent\" style=\"color:#777777;\">Is your $direction traffic rate limited?</h3>";

		$noise_warning = "";
		if(($diff_res[$n] == NOISE) || ($diff_res[$n+2] == NOISE) || ($diff_res[$n+4] == NOISE) || ($diff_res[$n+6] == NOISE))
		{
			$noise_warning = "<br><span style=\"font-style:normal;\">However, some of the measurements were affected by noise, which limits Glasnost ability to detect rate limiting.</span>";
		}

		if(($diff_res[$n] == YES) || ($diff_res[$n+2] == YES) || ($diff_res[$n+4] == YES) || ($diff_res[$n+6] == YES))
		{
			echo "<p class=\"indent2\"><span style=\"color:red;font-weight:bold;\">Your ISP appears to rate limit your ${direction}s.</span> $noise_warning</p>\n";
	}
	elseif(($diff_res[$n] == NOISE) && ($diff_res[$n+2] == NOISE) && ($diff_res[$n+4] == NOISE) && ($diff_res[$n+6] == NOISE))
	{
		echo "<p class=\"indent2\"><span style=\"color:black;font-weight:bold;\">The measurement data is too noisy
				to detect whether your ISP rate limits your $direction traffic.</span>
				Re-running the test while ensuring that no other downloads or uploads are running in the background might
				fix this problem.				
				</p>\n";
		continue;
	}
	elseif(($diff_res[$n] == NO) && ($diff_res[$n+2] == NO) && ($diff_res[$n+4] == NO) && ($diff_res[$n+6] == NO))
	{
		echo "<p class=\"indent2\"><span style=\"color:green;font-weight:bold;\">There is no indication that your ISP
				rate limits your ${direction}s.</span> $noise_warning</p>\n";
		continue;
		}

		else
		{
			echo "<p class=\"indent2\"><span style=\"color:green;font-weight:bold;\">There is no indication that your ISP
				rate limits your ${direction}s.</span> $noise_warning</p>\n";			
			/*				<br>However, some of the measurement data is too noisy to detect whether your ISP limits your
				$direction traffic. To fix this, please re-run the test and ensure that you do not have other downloads
				or uploads running on your host.";
				# continue;
				*/
		}

		echo "<p class=\"indent2\" style=\"font-style:italic;margin-bottom:-7px;\">Details:</p>
			<div style=\"margin-left:45px;border-left:1px dashed #777777;\">\n";

		/*
		 # (a) App+port-based? (this is kind of complex to determine)
		 if(1) # Noise is too high
		 {
			echo "<p class=\"indent\">
			<img src=\"pics/square.png\" alt=\"*\" style=\"margin-right:5px;margin-left:5px;margin-bottom:3px;\">
			<span style=\"color:black;font-weight:bold;\">The measurement data is too noisy to detect whether your
			ISP limits your $protocol1 ${direction}s.</span>
			To fix this, please re-run the test and ensure that you do not have other downloads or uploads running
			on your host.</p>\n";
			}
			else
			{
			if(1) # Differentiation!
			{
			echo "<p class=\"indent\">
			<img src=\"pics/square.png\" alt=\"*\" style=\"margin-right:5px;margin-left:5px;margin-bottom:3px;\">
			<span style=\"color:red;font-weight:bold;\">Your ISP possibly rate limits your $protocol1
			${direction}s.</span>
			In our tests a" . (($direction == "upload")?"n":"") . " $direction using a control flow achieved
			$max_cf Kbps while a $protocol1 $direction achieved $max_pr Kbps.</p>\n";
			}
			else # No differentiation!
			{
			echo "<p class=\"indent\">
			<img src=\"pics/square.png\" alt=\"*\" style=\"margin-right:5px;margin-left:5px;margin-bottom:3px;\">
			<span style=\"color:green;font-weight:bold;\">There is no indication that your ISP rate limits
			your $protocol1 ${direction}s.</span>
			In our tests a" . (($direction == "upload")?"n":"") . " $direction with a control flow achieved
			$max_cf Kbps while a $protocol1 $direction achieved $max_pr Kbps.</p>\n";
			}
			}
			*/

		# (b) App-based?
		if(($diff_res[$n] == NOISE) && ($diff_res[4+$n] == NOISE)) # Noise is too high
		{
			echo "<p class=\"indent\">
				<img src=\"pics/square.png\" alt=\"*\" style=\"margin-right:5px;margin-left:5px;margin-bottom:3px;\">
				<span style=\"color:black;font-weight:bold;\">The measurement data is too noisy to detect whether your
				ISP rate limits your $protocol1 ${direction}s.</span>
				Re-running the test while ensuring that no other downloads or uploads are running in the background might
				fix this problem.				
				</p>\n";
		}
		else
		{
			if(($diff_res[$n] == YES) || ($diff_res[4+$n] == YES)) # Differentiation!
			{
				if($diff_res[$n] == YES)
				{
					$max_cf = $diff_detail[$n][0];
					$max_pr = $diff_detail[$n][1];
				}
				if($diff_res[4+$n] == YES)
				{
					$max_cf = $diff_detail[4+$n][0];
					$max_pr = $diff_detail[4+$n][1];
				}

				echo "<p class=\"indent\">
					<img src=\"pics/square.png\" alt=\"*\" style=\"margin-right:5px;margin-left:5px;margin-bottom:3px;\">
					<span style=\"color:red;font-weight:bold;\">Your ISP appears to rate limit your $protocol1 
					${direction}s.</span>
					In our tests, ${direction}s using control flows achieved up to
					$max_cf Kbps while ${direction}s using $protocol1 achieved up to $max_pr Kbps.</p>\n";
			}
			else # No differentiation!
			{
				if($diff_res[$n] == NO)
				{
					$max_cf = $diff_detail[$n][0];
					$max_pr = $diff_detail[$n][1];
				}
				if($diff_res[4+$n] == NO)
				{
					$max_cf = $diff_detail[4+$n][0];
					$max_pr = $diff_detail[4+$n][1];
				}

				echo "<p class=\"indent\">
					<img src=\"pics/square.png\" alt=\"*\" style=\"margin-right:5px;margin-left:5px;margin-bottom:3px;\">
					<span style=\"color:green;font-weight:bold;\">There is no indication that your ISP rate limits 
					your $protocol1 ${direction}s.</span>
					In our tests, ${direction}s using control flows achieved up to 
					$max_cf Kbps while ${direction}s using $protocol1 achieved up to $max_pr Kbps.</p>\n";
			}
		}

		# (c) Port-based?
		if(($diff_res[2+$n] == NOISE) && ($diff_res[6+$n] == NOISE)) # Noise is too high
		{
			echo "<p class=\"indent\">
				<img src=\"pics/square.png\" alt=\"*\" style=\"margin-right:5px;margin-left:5px;margin-bottom:3px;\">
				<span style=\"color:black;font-weight:bold;\">The measurement data is too noisy to detect whether your
				ISP rate limits traffic on port $port1.</span>
				Re-running the test while ensuring that no other downloads or uploads are running in the background might
				fix this problem.				
				</p>\n";
		}
		else
		{
			if(($diff_res[2+$n] == YES) || ($diff_res[6+$n] == YES)) # Differentiation!
			{
				if($diff_res[2+$n] == YES)
				{
					$max_cf = $diff_detail[2+$n][0];
					$max_pr = $diff_detail[2+$n][1];
					$diff_port = $diff_detail[2+$n][2];
				}
				if($diff_res[6+$n] == YES)
				{
					$max_cf = $diff_detail[6+$n][0];
					$max_pr = $diff_detail[6+$n][1];
					$diff_port = $diff_detail[6+$n][2];
				}

				echo "<p class=\"indent\">
					<img src=\"pics/square.png\" alt=\"*\" style=\"margin-right:5px;margin-left:5px;margin-bottom:3px;\">
					<span style=\"color:red;font-weight:bold;\">Your ISP appears to rate limit ${direction}s on port 
					$diff_port.</span>
					In our tests, ${direction}s on port $port1 achieved up to $max_cf Kbps
					while ${direction}s on port $port2 achieved up to $max_pr Kbps.</p>\n";	
			}
			else # No differentiation!
			{
				if($diff_res[2+$n] == NO)
				{
					$max_cf = $diff_detail[2+$n][0];
					$max_pr = $diff_detail[2+$n][1];
				}
				if($diff_res[6+$n] == NO)
				{
					$max_cf = $diff_detail[6+$n][0];
					$max_pr = $diff_detail[6+$n][1];
				}

				echo "<p class=\"indent\">
					<img src=\"pics/square.png\" alt=\"*\" style=\"margin-right:5px;margin-left:5px;margin-bottom:3px;\">
					<span style=\"color:green;font-weight:bold;\">There is no indication that your ISP rate limits 
					${direction}s on port $port1 or $port2.</span>
					In our tests, ${direction}s on port $port1 achieved up to $max_cf Kbps
					while ${direction}s on port $port2 achieved up to $max_pr Kbps.</p>\n";
			}
		}echo "</div>\n";
	}


	$params = "";
	if(isset($protocol1)){ $params = $params."protocol1=${protocol1}&"; }
	if(isset($protocol2)){ $params = $params."protocol2=${protocol2}&"; }
	if(isset($port1)){ $params = $params."port=${port1}&"; }
	if(isset($port2)){ $params = $params."port2=${port2}&"; }

	if($dir[0] == UPLOAD) { $params .= "dir=" . UPLOAD . ';' . DOWNLOAD . '&'; }
	else { $params .= "dir=" . DOWNLOAD . ';' . UPLOAD . '&'; }

	for($n=0; $n<8; $n++)
	{
		$params .= "flow${n}=$type_bpslist[$n]&";
	}

	$params = $params."details=yes";

	echo "<br><p class=\"indent\" style=\"font-style:italic;\"><img src=\"http://broadband.mpi-sws.org/transparency/info.png\"> You can view the <a href=\"http://$this_script?${params}\" target=\"_blank\">detailed measurement results of the test here</a>.<!--/p-->";
	
	if($download_logs)
	{
		echo "<br><img src=\"http://broadband.mpi-sws.org/transparency/info.png\"> For a more detailed analysis, you can download the 
	   <a href=\"http://$server:19981/?retrieve=log&amp;id=$ts&amp;hostname=$hostname&amp;ip=$hostip\">log file</a> and 
	   <a href=\"http://$server:19981/?retrieve=dump&amp;id=$ts&amp;hostname=$hostname&amp;ip=$hostip\">packet-level trace</a> Glasnost collected of your test run.\n";	   
	}
	
	echo "</p><p class=\"indent\" style=\"font-style:italic;\">For more details on how Glasnost tests work, please
	<!-- follow <a href=\"http://broadband.mpi-sws.org/transparency/testdetails.html\" target=\"_blank\">this link</a>. -->
	read our <a href=\"http://broadband.mpi-sws.org/transparency/results/10_nsdi_glasnost.pdf\">NSDI 2010 paper</a>.
	</p>";

	
	echo "<br><p style=\"padding-top:5px;border-top:1px solid #69acff;\"><br>
	       For details on our research on broadband networks please refer to our
	       <a href=\"http://broadband.mpi-sws.org/transparency/\">network transparency project webpage</a><br>
	
	    In case you have questions about this tool or our research, please contact us: 
		<img src=\"http://broadband.mpi-sws.org/pics/email.png\" alt=\"broadband @at@ mpi-sws mpg de\" style=\"margin-left:5px;margin-bottom:-6px;\"></p>
	    </div>
	";

	echo "</body></html>";

	# Store what we showed to the user
	#  $htmlfile = sprintf("bt_%s_%s_%d.html", $hostip, $hostname, $ts);
	#  $fp = fopen("${store_directory}/$htmlfile", "w");
	#  fwrite($fp, ob_get_contents());
	#  fclose($fp);

	# Now send all content to the user
	ob_end_flush();

	# Log to file
	#  $http_info = "Referer=".@$_SERVER['HTTP_REFERER']."&User-Agent=".@$_SERVER['HTTP_USER_AGENT']."&Accept-Charset=".@$_SERVER['HTTP_ACCEPT_CHARSET'];
	#  log_to_file("${store_directory}/bttest.stats", "$ts;$hostname;$hostip;success;".@$_GET['server'].';'.@$_GET['sysinfo'].';'.$args.';'.$http_info.";\n");

	exit(0);
}

###############################################################################
# For the bandwidth comparison, display detailed tables with individual results
###############################################################################
function show_details($warnings = null)
{
	global $title, $subtitle;

	if(isset($_GET['port'])){
		$port1 = $_GET['port'];
	}
	if(isset($_GET['port2'])){
		$port2 = $_GET['port2'];
	}

	if(isset($_GET['protocol1'])){
		$protocol1 = $_GET['protocol1'];
	}
	if(isset($_GET['protocol2'])){
		$protocol2 = $_GET['protocol2'];
	}
	else {
		$protocol2 = "control flow";
	}

	if(!isset($_GET['dir']))
	{
		echo "<p style=\"color:red;font-weight:bold;padding:10px;border:1px;\">DEBUG: Parameter 'dir' missing.</p>";
	}


	if($_GET['dir'] == DOWNLOAD.';'.UPLOAD)
	{
		# port1
		if(isset($_GET['flow1'])){
			$cfdown = split(';', $_GET['flow1']);
		}
		if(isset($_GET['flow5'])){
			$cfup = split(';', $_GET['flow5']);
		}
		if(isset($_GET['flow0'])){
			$prdown = split(';', $_GET['flow0']);
		}
		if(isset($_GET['flow4'])){
			$prup = split(';', $_GET['flow4']);
		}

		# port2
		if(isset($_GET['flow3'])){
			$cfdown2 = split(';', $_GET['flow3']);
		}
		if(isset($_GET['flow7'])){
			$cfup2 = split(';', $_GET['flow7']);
		}
		if(isset($_GET['flow2'])){
			$prdown2 = split(';', $_GET['flow2']);
		}
		if(isset($_GET['flow6'])){
			$prup2 = split(';', $_GET['flow6']);
		}
	}
	else
	{
		# port1
		if(isset($_GET['flow5'])){
			$cfdown = split(';', $_GET['flow5']);
		}
		if(isset($_GET['flow1'])){
			$cfup = split(';', $_GET['flow1']);
		}
		if(isset($_GET['flow4'])){
			$prdown = split(';', $_GET['flow4']);
		}
		if(isset($_GET['flow0'])){
			$prup = split(';', $_GET['flow0']);
		}

		# port2
		if(isset($_GET['flow7'])){
			$cfdown2 = split(';', $_GET['flow7']);
		}
		if(isset($_GET['flow3'])){
			$cfup2 = split(';', $_GET['flow3']);
		}
		if(isset($_GET['flow6'])){
			$prdown2 = split(';', $_GET['flow6']);
		}
		if(isset($_GET['flow2'])){
			$prup2 = split(';', $_GET['flow2']);
		}
	}


	echo "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">
		<html>
		  <head>
		    <title>$title</title>
		    <meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">
		    <link rel=\"stylesheet\" href=\"mpi.css\" type=\"text/css\">
		    <link rel=\"shortcut icon\" href=\"./favicon.ico\" type=\"image/vnd.microsoft.icon\">
		    <link rel=\"icon\" href=\"./favicon.ico\" type=\"image/vnd.microsoft.icon\"> 
		  </head>
		
		  <body>
		    <a href=\"http://www.mpi-sws.org\"><img src=\"pics/mpisws-logo.png\" alt=\"MPI-SWS\" style=\"border:0px;background-color:white;vertical-align:bottom;\"></a>
		    <h1 style=\"font-family:serif;\">$title$subtitle</h1>
		
		  <div style=\"width:75%;border:1px solid #69acff;padding:15px;\">
		    
		    <div style=\"border-bottom:1px solid #69acff;font-family:serif;font-weight:bold;\">
		      Detailed test results giving the throughput per flow Glasnost runs:</div>    
		";

	if(count(@$warnings) > 0){
		echo "<p style=\"border:1px solid #ff7200; padding:10px; color: #ff7200;\">";
		for($i=0; $i<count($warnings); $i++){
			if($i > 0){ echo "<br>"; }
			echo "$warnings[$i]<br>\n";
		}
		echo "</p>";
	}

	function detailsTableHeader($protocol1, $protocol2, $port){
		echo "<h3 class=\"indent\" style=\"color:#777777;\">All $protocol1 and $protocol2 transfers using port $port</h3>";

		$proto1 = $protocol1;
		if(substr($proto1, strlen($proto1) - 4) != "flow")
		{
			$proto1 = $proto1 . " flow";
		}
		$proto2 = $protocol2;
		if(substr($proto2, strlen($proto2) - 4) != "flow")
		{
			$proto2 = $proto2 . " flow";
		}

		echo "<p style=\"padding-left:30px;\">
	           <table class=\"box\" cellspacing=\"1\">
	            <tr>
	             <th class=\"box box2\">Transfer Direction</th>
	             <th class=\"box box2\">Bandwidth $proto1</th>
	             <th class=\"box box2\">Bandwidth $proto2</th>
	            </tr>
	     		<tr><td colspan=\"3\" class=\"spacer\">&nbsp;</td></tr>		
	          ";
	}

	function detailsTableHeader2($protocol2, $port1, $port2){
		echo "<h3 class=\"indent\" style=\"color:#777777;\">".ucfirst($protocol2)." transfers using port $port1 and port $port2</h3>";

		echo "<p style=\"padding-left:30px;\">
	           <table class=\"box\" cellspacing=\"1\">
	            <tr>
	             <th class=\"box box2\">Transfer Direction</th>
	             <th class=\"box box2\">Bandwidth Port $port1</th>
	             <th class=\"box box2\">Bandwidth Port $port2</th>
	            </tr>
	            <tr><td colspan=\"3\" class=\"spacer\">&nbsp;</td></tr>
	          ";
	}


	if(isset($port1)){

		$firstentry = 1;
		$i = 0;
		while(isset($cfdown[$i]) && isset($prdown[$i]) && $cfdown[$i] != "" && $prdown[$i] != ""){

			if($firstentry == 1){
				detailsTableHeader($protocol1, $protocol2, $port1);
				$firstentry = 0;
			}

			if(is_numeric($cfdown[$i])){ $cfdown[$i] .= " Kbps"; }
			if(is_numeric($prdown[$i])){ $prdown[$i] .= " Kbps"; }
				
			printf("<tr><td class=\"box\">Download #".($i+1)."</td>
                  <td style=\"text-align:right;\" class=\"box\">$prdown[$i]</td>
                  <td style=\"text-align:right;\" class=\"box\">$cfdown[$i]</td>
              		");

			echo "</tr>";
				
			$i++;
		}
		if($firstentry == 0){
			echo "<tr><td colspan=\"3\" class=\"spacer\">&nbsp;</td></tr>\n";
		}

		$i = 0;
		while(isset($cfup[$i]) && isset($prup[$i]) && $cfup[$i] != "" && $prup[$i] != ""){

			if(is_numeric($cfup[$i])){ $cfup[$i] .= " Kbps"; }
			if(is_numeric($prup[$i])){ $prup[$i] .= " Kbps"; }
				
			if($firstentry == 1){
				detailsTableHeader($protocol1, $protocol2, $port1);
				$firstentry = 0;
			}

			printf("<tr><td class=\"box\">Upload #".($i+1)."</td>
                  <td style=\"text-align:right;\" class=\"box\">$prup[$i]</td>
                  <td style=\"text-align:right;\" class=\"box\">$cfup[$i]</td>
             	 ");

			echo "</tr>";
				
			$i++;
		}

		if($firstentry == 0){
			echo "</table>";
			echo "<p>&nbsp;</p>";
		}
	}

	if(isset($port2)){

		$firstentry = 1;
		$i = 0;
		while(isset($cfdown2[$i]) && isset($prdown2[$i]) && $cfdown2[$i] != "" && $prdown2[$i] != ""){

			if(is_numeric($cfdown2[$i])){ $cfdown2[$i] .= " Kbps"; }
			if(is_numeric($prdown2[$i])){ $prdown2[$i] .= " Kbps"; }

			if($firstentry == 1){
				detailsTableHeader($protocol1, $protocol2, $port2);
				$firstentry = 0;
			}

			printf("<tr><td class=\"box\">Download #".($i+1)."</td>
                  <td style=\"text-align:right;\" class=\"box\">$prdown2[$i]</td>
                  <td style=\"text-align:right;\" class=\"box\">$cfdown2[$i]</td>
             	 ");

			echo "</tr>";
				
			$i++;
		}
		if($firstentry == 0){
			echo "<tr><td colspan=\"3\" class=\"spacer\">&nbsp;</td></tr>\n";
		}

		$i = 0;
		while(isset($cfup2[$i]) && isset($prup2[$i]) && $cfup2[$i] != "" && $prup2[$i] != ""){

			if(is_numeric($cfup2[$i])){ $cfup2[$i] .= " Kbps"; }
			if(is_numeric($prup2[$i])){ $prup2[$i] .= " Kbps"; }

			if($firstentry == 1){
				detailsTableHeader($protocol1, $protocol2, $port2);
				$firstentry = 0;
			}

			printf("<tr><td class=\"box\">Upload #".($i+1)."</td>
                  <td style=\"text-align:right;\" class=\"box\">$prup2[$i]</td>
                  <td style=\"text-align:right;\" class=\"box\">$cfup2[$i]</td>
              	");

			echo "</tr>";

			$i++;
		}

		if($firstentry == 0){
			echo "</table>";
			echo "<p>&nbsp;</p>";
		}


		# Now check if traffic is rate limited if it used a well-known BT port

		$firstentry = 1;
		$i = 0;
		while(isset($prdown2[$i]) && isset($prdown[$i]) && $prdown2[$i] != "" && $prdown[$i] != ""){

			if(is_numeric($prdown2[$i])){ $prdown2[$i] .= " Kbps"; }
			if(is_numeric($prdown[$i])){ $prdown[$i] .= " Kbps"; }

			if($firstentry == 1){
				detailsTableHeader2($protocol1, $port1, $port2);
				$firstentry = 0;
			}

			printf("<tr><td class=\"box\">Download #".($i+1)."</td>
                  <td style=\"text-align:right;\" class=\"box\">$prdown[$i]</td>
                  <td style=\"text-align:right;\" class=\"box\">$prdown2[$i]</td>
        	      ");

			echo "</tr>";

			$i++;
		}
		if($firstentry == 0){
			echo "<tr><td colspan=\"3\" class=\"spacer\">&nbsp;</td></tr>\n";
		}

		$i = 0;
		while(isset($prup2[$i]) && isset($prup[$i]) && $prup2[$i] != "" && $prup[$i] != ""){

			if(is_numeric($prup2[$i])){ $prup2[$i] .= " Kbps"; }
			if(is_numeric($prup[$i])){ $prup[$i] .= " Kbps"; }
				
			if($firstentry == 1){
				detailsTableHeader2($protocol1, $port1, $port2);
				$firstentry = 0;
			}

			printf("<tr><td class=\"box\">Upload #".($i+1)."</td>
                  <td style=\"text-align:right;\" class=\"box\">$prup[$i]</td>
                  <td style=\"text-align:right;\" class=\"box\">$prup2[$i]</td>
        	      ");

			echo "</tr>";

			$i++;
		}

		if($firstentry == 0){
			echo "</table>";
			echo "<p>&nbsp;</p>";
		}


		$firstentry = 1;
		$i = 0;
		while(isset($cfdown2[$i]) && isset($cfdown[$i]) && $cfdown2[$i] != "" && $cfdown[$i] != ""){

			if(is_numeric($cfdown2[$i])){ $cfdown2[$i] .= " Kbps"; }
			if(is_numeric($cfdown[$i])){ $cfdown[$i] .= " Kbps"; }

			if($firstentry == 1){
				detailsTableHeader2($protocol2, $port1, $port2);
				$firstentry = 0;
			}

			printf("<tr><td class=\"box\">Download #".($i+1)."</td>
                  <td style=\"text-align:right;\" class=\"box\">$cfdown[$i]</td>
                  <td style=\"text-align:right;\" class=\"box\">$cfdown2[$i]</td>
        	      ");

			echo "</tr>";

			$i++;
		}
		if($firstentry == 0){
			echo "<tr><td colspan=\"3\" class=\"spacer\">&nbsp;</td></tr>\n";
		}

		$i = 0;
		while(isset($cfup2[$i]) && isset($cfup[$i]) && $cfup2[$i] != "" && $cfup[$i] != ""){

			if(is_numeric($cfup2[$i])){ $cfup2[$i] .= " Kbps"; }
			if(is_numeric($cfup[$i])){ $cfup[$i] .= " Kbps"; }
				
			if($firstentry == 1){
				detailsTableHeader2($protocol2, $port1, $port2);
				$firstentry = 0;
			}

			printf("<tr><td class=\"box\">Upload #".($i+1)."</td>
                  <td style=\"text-align:right;\" class=\"box\">$cfup[$i]</td>
                  <td style=\"text-align:right;\" class=\"box\">$cfup2[$i]</td>
        	      ");

			echo "</tr>";

			$i++;
		}

		if($firstentry == 0){
			echo "</table>";
			echo "<p>&nbsp;</p>";
		}
	}

	echo "
	    <p>&nbsp;</p>
	    <p style=\"padding-top:5px;border-top:1px solid #69acff;\">
	       For details on our research on broadband networks please refer to our
	       <a href=\"http://broadband.mpi-sws.org/transparency/\">network transparency project webpage</a></p>
	
	    <p>In case you have questions about this tool or our research, please contact us: 
	<img src=\"http://broadband.mpi-sws.org/pics/email.png\" alt=\"broadband @at@ mpi-sws mpg de\" style=\"margin-left:5px;margin-bottom:-6px;\"></p>
	   </div>
	  </body>
	</html>
	";

	exit(0);
}


function get_detailed_results($warn_msg = null)
{
	global $title, $subtitle, $store_directory, $this_script;
	global $noise_thres, $diff_thres;


	if(isset($warn_msg) && ($warn_msg != "")){
		$warning[] = $warn_msg;
	}
	
	# Read in all parameters passed from the applet
	while($p = each($_GET))
	{
		if($p[0] == "done"){}
		elseif($p[0] == "internal"){}
		elseif($p[0] == "down"){}
		elseif($p[0] == "up"){}
		elseif($p[0] == "protocol1"){
			$protocol1 = $p[1];
		}
		elseif($p[0] == "protocol2"){
			$protocol2 = $p[1];
		}
		elseif($p[0] == "duration"){}
		elseif($p[0] == "sysinfo"){}
		elseif($p[0] == "id"){}
		elseif($p[0] == "server"){}
		elseif($p[0] == "peer"){}
		elseif($p[0] == "hostname"){}
		elseif($p[0] == "port"){
			$port1 = $p[1];
		}
		elseif($p[0] == "port2"){
			$port2 = $p[1];
		}
		elseif($p[0] == "repeat"){
			$repeat = $p[1];
		}

		# Now read what the client found
		elseif(preg_match('/^expu\d+/', $p[0])){
			$index = substr($p[0], 4); # Just give me the number at the end
			$expu[$index] = $p[1];
			if(! isset($expr[$index])){ $expr[$index] = 0; }
		}
		elseif(preg_match('/^expd\d+/', $p[0])){
			$index = substr($p[0], 4); # Just give me the number at the end
			$expd[$index] = $p[1];
			if(! isset($expr[$index])){ $expr[$index] = 0; }
		}
		elseif(preg_match('/^expl\d+/', $p[0])){
			$index = substr($p[0], 4); # Just give me the number at the end
			$expl[$index] = $p[1];
		}
		elseif(preg_match('/^expr\d+/', $p[0])){
			$index = substr($p[0], 4); # Just give me the number at the end
			$expr[$index] = $p[1];
		}
		elseif(preg_match('/^expstate\d+/', $p[0])){}
		elseif(preg_match('/^expp\d+/', $p[0])){
			$index = substr($p[0], 4); # Just give me the number at the end
			$port[$index] = $p[1];
		}
		elseif(preg_match('/^expprot\d+/', $p[0])){}
		elseif(preg_match('/^expserv\d+/', $p[0])){}

		# Server side
		elseif(preg_match('/^expsu\d+/', $p[0])){
			$index = substr($p[0], 5); # Just give me the number at the end
			$expsu[$index] = $p[1];
			if(! isset($expsr[$index])){ $expsr[$index] = 0; }
			if(! isset($expsrs[$index])){ $expsrs[$index] = 0; }
		}
		elseif(preg_match('/^expsd\d+/', $p[0])){
			$index = substr($p[0], 5); # Just give me the number at the end
			$expsd[$index] = $p[1];
			if(! isset($expsr[$index])){ $expsr[$index] = 0; }
			if(! isset($expsrs[$index])){ $expsrs[$index] = 0; }
		}
		elseif(preg_match('/^expsl\d+/', $p[0])){
			$index = substr($p[0], 5); # Just give me the number at the end
			$expsl[$index] = $p[1];
		}
		elseif(preg_match('/^expsr\d+/', $p[0])){
			$index = substr($p[0], 5); # Just give me the number at the end
			$expsr[$index] = $p[1];
		}
		elseif(preg_match('/^expsrs\d+/', $p[0])){
			$index = substr($p[0], 5); # Just give me the number at the end
			$expsrs[$index] = $p[1];
		}
		elseif(preg_match('/^expsstate\d+/', $p[0])){}

		# DEBUG ONLY
		else{
			echo "<p style=\"color:red\">DEBUG: Unknown Parameter: \"$p[0]=$p[1]\"</p>";
		}
	}

	if(! isset($repeat)){
		echo "<p style=\"color:red\">ERROR: Repeat parameter not set. Assuming 3, but this is likely to be wrong.</p>";
		$repeat = 3;
	}

	if(! isset($protocol2)){
		$protocol2 = "control flow";
	}

	# Check ports used
	if($port1 <= 0){ # runs 0..(($repeat*2)-1), ($repeat*4)..(($repeat*6)-1)
		$port1_orig = $port1;
		$port1 = $port[0];
	}
	if($port2 <= 0){ # runs ($repeat*2)..($repeat*4)-1), ($repeat*6)..(($repeat*8)-1)
		$port2_orig = $port2;
		$port2 = $port[($repeat*2)];
	}

	$p = 0;
	for($i=0; $i<($repeat*2); $i++){
		$p += $port[$i];
	}
	for($i=($repeat*4); $i<($repeat*6); $i++){
		$p += $port[$i];
	}
	if($p != ($port[0]*($repeat*4))){
		$warning[] = "<b>Attention:</b> The first TCP port used ($port1) changed during the test. This was done at the measurement server as the port was occupied. Be aware that this can affect the correctness of the results.";
	}

	$p = 0;
	for($i=($repeat*2); $i<($repeat*4); $i++){
		$p += $port[$i];
	}
	for($i=($repeat*6); $i<($repeat*8); $i++){
		$p += $port[$i];
	}
	if($p != ($port[($repeat*2)]*($repeat*4))){
		$warning[] = "<b>Attention:</b> The second TCP port used ($port2) changed during the test. This was done at the measurement server as the port was occupied. Be aware that this can affect the correctness of the results.";
	}

	if(count(@$warning) == 0){
		if($port[0] != $port1){
			$warning[] = "<b>Note:</b> The server changed the requested port $port1 to $port[0] as the original port was occupied.";
			$port1_orig = $port1;
			$port1 = $port[0];
		}
		if($port[($repeat*2)] != $port2){
			$warning[] = "<b>Note:</b> The server changed the requested port $port2 to ".$port[($repeat*2)]." as the original port was occupied.";
			$port2_orig = $port2;
			$port2 = $port[($repeat*2)];
		}
	}

	# Sanity checks

	$port1_failed = 0;
	$port2_failed = 0;

	# First-port runs
	$length_check = 0;
	for($i=0; $i<($repeat*2); $i++){
		$length_check += $expsl[$i];
		if($length_check > 0){ break; }
	}
	if($length_check == 0){
		for($i=($repeat*4); $i<($repeat*6); $i++){
			$length_check += $expsl[$i];
			if($length_check > 0){ break; }
		}
	}
	if($length_check == 0){
		$port1_failed = 1;
	}

	# Second-port runs
	$length_check = 0;
	for($i=($repeat*2); $i<($repeat*4); $i++){
		$length_check += $expsl[$i];
		if($length_check > 0){ break; }
	}
	if($length_check == 0){
		for($i=($repeat*6); $i<($repeat*8); $i++){
			$length_check += $expsl[$i];
			if($length_check > 0){ break; }
		}
	}
	if($length_check == 0){
		$port2_failed = 1;
	}

	# Sanity check for short tests
	if(1)
	{
		$avg_duration = 0;
		$num_exp = 0;
		for($i=0; $i<count($expu); $i++){
			if(($expu[$i] <= 0) && ($expd[$i] <= 0) && ($expsd[$i] <= 0) && ($expsu[$i] <= 0)){ next; }
			
			if(isset($expl[$i]) && isset($expsl[$i])){
				$avg_duration += max($expl[$i], $expsl[$i]);
				$num_exp++;
			}
			elseif(isset($expl[$i])){
				$avg_duration += $expl[$i];
				$num_exp++;
			}
			elseif(isset($expsl[$i])){
				$avg_duration += $expsl[$i];
				$num_exp++;
			}
		}
		if($num_exp > 5){
			$avg_duration /= $num_exp;
			
			if($avg_duration < MIN_TEST_DURATION){ # in seconds
				$warning[] = "<b>Warning:</b> The average duration of your test flows was only ".round($avg_duration,2)." seconds.  Measurements from short duration flows tend to be more noisy, which leads to less accurate results. We recommend that you configure the test flows to run for longer than ".MIN_TEST_DURATION." seconds.";
			}
		}
	}
	
	# Get noise and max tput for each flow type
	####################

	# 0: protocol1 upstream port1
	# 1: protocol2 upstream port1
	# 2: protocol1 upstream port2
	# 3: protocol2 upstream port2
	# 4: protocol1 downstream port1
	# 5: protocol2 downstream port1
	# 6: protocol1 downstream port2
	# 7: protocol2 downstream port2


	$dir = array();
	$uncertainty = 0;
	# Decide which of the flows are uploads and which are downloads
	for($n=0; $n<2; $n++)
	{
		$up = 0; $down = 0;
		for($i=0; $i<$repeat*4; $i++)
		{
			if(isset($expd[$n*$repeat*4+$i]) && isset($expsd[$n*$repeat*4+$i]))
			{
				if($expd[$n*$repeat*4+$i] > $expsd[$n*$repeat*4+$i]) { $down++; }
				elseif($expd[$n*$repeat*4+$i] < $expsd[$n*$repeat*4+$i]) { $up++; }
				else # use default
				{
					if($n == 0){ $up++; }
					else { $down++; }
				}
			}
		}

		if($up > $down){ $dir[$n] = UPLOAD; }
		elseif($up < $down){ $dir[$n] = DOWNLOAD; }
		elseif($n == 0){ $dir[$n] = UPLOAD; }
		else { $dir[$n] = DOWNLOAD; }

		$uncertainty = max($uncertainty, 1/abs($up-$down));
	}

	if(($dir[0] == $dir[1]) || ($uncertainty > (1/$repeat)))
	{
		$warning[] = "<b>Warning:</b> Direction detection failed. The test results might not be correct as Glasnost was designed for server-based workloads with large downloads.";
	}

	$type_bpslist = array();

	for($n=0; $n<8; $n++)
	{
		if($n == 0) { $base = 0; $port = $port1; }
		elseif($n == 1) { $base = 1; $port = $port1; }
		elseif($n == 2) { $base = 2*$repeat; $port = $port2; }
		elseif($n == 3) { $base = 2*$repeat+1; $port = $port2; }
		elseif($n == 4) { $base = 4*$repeat; $port = $port1; }
		elseif($n == 5) { $base = 4*$repeat+1; $port = $port1; }
		elseif($n == 6) { $base = 6*$repeat; $port = $port2; }
		elseif($n == 7) { $base = 6*$repeat+1; $port = $port2; }

		$bps = array(); # Reset
		$bps_list = "";
		$sane = 1;

		for($i=0; $i<$repeat; $i++)
		{
			if(!isset($expl[$base+$i*2]) || !($expl[$base+$i*2] > 0))
			{
				$sane = 0;
				break;
			}
		}

		if($n < 4){ $direction = $dir[0]; }
		else { $direction = $dir[1]; }

		if($sane == 1)
		{
			# Quantify noise and get max
			for($i=0; $i<$repeat; $i++)
			{
				if($direction == DOWNLOAD)
				{
					if(isset($expd[$base+$i*2]) && ($expd[$base+$i*2] > 0))
					{
						$bps[] = sprintf("%d", (int)(0.008* $expd[$base+$i*2] / $expl[$base+$i*2]));
						$bps_list = sprintf("%s;%d", $bps_list, $bps[count($bps)-1]);
					}
					else
					{
						$bps_list = sprintf("%s;failed", $bps_list);
					}
				}
				elseif($direction == UPLOAD)
				{
					if(isset($expsd[$base+$i*2]) && ($expsd[$base+$i*2] > 0))
					{
						$bps[] = sprintf("%d", (int)(0.008* $expsd[$base+$i*2] / $expsl[$base+$i*2]));
						$bps_list = sprintf("%s;%d", $bps_list, $bps[count($bps)-1]);
					}
					else
					{
						$bps_list = sprintf("%s;failed", $bps_list);
					}
				}
			}
				
			if(count($bps) > 0)
			{
				$bps = array(); # Reset
				$type_bpslist[$n] = substr($bps_list, 1);
			}
		}
	}

	$_GET['details'] = "yes";
	if(isset($port1)){ $_GET['port'] = $port1; }
	if(isset($port2)){ $_GET['port2'] = $port2; }
	if($dir[0] == UPLOAD) { $_GET['dir'] = UPLOAD . ';' . DOWNLOAD . '&'; }
	else { $_GET['dir'] = DOWNLOAD . ';' . UPLOAD . '&'; }

	for($n=0; $n<8; $n++)
	{
		$_GET["flow${n}"] = $type_bpslist[$n];
	}

	show_details($warning);

	exit(0);
}


?>
