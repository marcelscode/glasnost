#!/opt/csw/bin/perl
use strict;

#
# This script connects to the gserver process on an MLab node and checks
# whether the node is operational.
# It outputs a new measurement-servers.php file and uploads it to the
# loki servers.
#
# This script requires the Net::Telnet module!
#
#
# Required parameter: Path to a file holding measurement server names
# Optional parameters:
#    -n : Do not upload new measurement-servers.php file
#    -c : Cronjob mode (non-NAGIOS mode): emails warnings to maintainer
#    -t : Output text file format;
# 	  active servers are logged to STDOUT, dead servers to STDERR
# 
#
# (c) Marcel Dischinger (MPI-SWS) 2010
# License: CC by-nc-sa
# ========================================================================== #
# Parameters:

my $key = '-i /SWS_1/.meta/scripts/measurementlab/.ssh/id_dsa_pl';
my $ssh_opt = "$key -o StrictHostKeyChecking=no";

use constant GPORT => 19981; # Glasnost default port
use constant TIMEOUT => 10; # in seconds

# Email address to send warnings if not enough servers are up
use constant MAINTAINER_EMAIL => 'mdischin@mpi-sws.org';
# Threshold for the minimum number of servers that must be up
use constant SERVER_THRESHOLD => 4;

# NAGIOS return values
use constant OK => 0;
use constant WARNING => 1;
use constant CRITICAL => 2;
use constant UNKNOWN => 3;

my $tempdir = '/tmp';

# ========================================================================== #

my (@active, @dead, @loki);
my $ifile;
my $auto = 1;
my $upload = 1;
my $cronmode = 0;

# Parse input parameters
while($_ = shift)
{
  if(/^-t$/)
  {
    $auto = 0;
  }
  elsif(/^-n$/)
  {
    $upload = 0;
    $auto = 1;
  }
  elsif(/^-c$/)
  {
    $cronmode = 1;
  }
  elsif(! defined $ifile)
  {
    $ifile = $_;
    if(! -s $ifile)
    {
      print "Script parameter: $ifile not found.\n";
      exit CRITICAL;
    }
  }
  else
  {
    print "Script parameter: Unknown parameter $_\n";
    exit CRITICAL;
  }
}

if(! defined $ifile || ! -s $ifile)
{
  print "Script paramter: No server input file or file missing.\n";
  exit CRITICAL;
}

my $num_servers = 0;
my $exitcode = OK;
my @OUTPUT;

# Go through input file and check whether servers are online
open(SERVERS, $ifile) or die $!;
while(<SERVERS>)
{
  chomp;
  # Parse measurement-servers.php file
  if(/^[\s\t]*#/)
  { 
    #print STDERR "Ignoring commented entry $_\n";
    next; 
  }
  
  my $server;
  if(/\'.+\'/)
  {
    my @l = split(/'/);
    
    next if(scalar @l < 2);
    $server = $l[1];
  }
  else
  {
    #print STDERR "Ignoring entry $_\n";
    next;
  }
  
  # This assumes that loki servers host the webpage and
  # want an updated measurement-servers.php
  if($server =~ /loki\d+.mpi-sws.mpg.de/)
  {
    $loki[@loki] = $server;
  }

  # Call remote watchdog in case service went down there
  runRemoteWatchdog($server);

  $num_servers++;
  
  if(hasEnoughDiskSpace($server) && isWritableDisk($server))
  {
    if(nodeIsUp($server))
    {
      $active[@active] = $server;
    }
    else
    {
      $dead[@dead] = $server;
    }
  }
  else
  {
    $exitcode = WARNING;
    $dead[@dead] = $server;
  }
}
close(SERVERS);

# Generate and upload measurement-servers.php file
if($auto == 1)
{
  my $now = time;
  
  if(scalar @active > 0)
  {
    #open(ACTIVE, ">${tempdir}/measurement-servers.php-${now}");
    open(ACTIVE, ">${tempdir}/measurement-servers.php-new");
    print ACTIVE "<?php
    # Measurement servers to load the applet from (gserver has to run there)
    # Created $now
    \$mlab_server = array (\n";
    
    for(my $i=0; $i < scalar @active; $i++)
    {
      print ACTIVE "'$active[$i]' " . (($i != $#active)? ", \n" : "\n");
    }
    
    print ACTIVE ");\n?>\n";
    close(ACTIVE);
    printf "%d of %d servers are online.\n", scalar @active, ((scalar @active) + (scalar @dead));
    
    # Upload file to lokis
    if($upload == 1)
    {
      $_ = `/opt/csw/bin/gdiff -BEwNy --suppress-common-lines ${tempdir}/measurement-servers.php-new ${tempdir}/measurement-servers.php | wc -l`; 
      chomp;
      $_ = sprintf("%d", $_);
      
      if($_ > 1) # The file contains a timestamp, so 1 change will always be present
      {
	for(my $i=0; $i < scalar @loki; $i++)
	{
	  #system("scp $ssh_opt ${tempdir}/measurement-servers.php-${now} root\@$loki[$i]:/var/www/bb/measurement-servers.php");
	  system("scp $ssh_opt ${tempdir}/measurement-servers.php root\@$loki[$i]:/var/www/bb/measurement-servers.php");
	}
      }
    }
    #unlink("${tempdir}/measurement-servers.php-${now}");
    system("mv ${tempdir}/measurement-servers.php-new ${tempdir}/measurement-servers.php");
    
    # Output from watchdog calls
    foreach my $line (@OUTPUT){
      print "$line\n";
    }
    
    if((scalar @active) < ($num_servers/2))
    {
      if($cronmode)
      {
	sendWarningEmail("Glasnost WARNING: Only " . (scalar @active) . " online", "$0 detected that only " . (scalar @active) . " servers are online.");
      }
      exit WARNING;
    }
    elsif((scalar @active) < SERVER_THRESHOLD)
    {
      # Uh, no active nodes. Warn maintainer!
      if($cronmode)
      {
	sendWarningEmail("Glasnost CRITICAL: Only " . (scalar @active) . " online", "$0 detected that only " . (scalar @active) . " servers are online.");
      }
      exit CRITICAL;
    }
  }
  
  exit $exitcode;
}

# Output simple list of online and offline servers
for(my $i=0; $i < scalar @active; $i++)
{
  print "$active[$i]\n";
}
for(my $i=0; $i < scalar @dead; $i++)
{
  print STDERR "$dead[$i]\n";
}

exit $exitcode;

# ========================================================================== #

# Pass name of remote host
# Optionally: the port the remote host is listening on
# Returns 1 if the node is up, 0 otherwise.
# This connects to a maintenance routine in Glasnost
sub nodeIsUp {

  use Net::Telnet;
  
  if(! defined $_[0]){ print "Script: Bad usage of sub checkNode!\n"; exit CRITICAL; }
  my $host = $_[0];
  
  my $port;
  if(defined $_[1] && ($_[1] =~ /^\d+$/)){ $port = $_[1]; }
  else { $port = GPORT; }
  
  my $t = new Net::Telnet ();
  my $ret = $t->open(Host => $host, Port => $port, Timeout => TIMEOUT, Errmode => "return");

  if(! defined $ret || $t->timed_out)
  {
    $t->close;
    
    push @OUTPUT, "$host is not available on port $port";
    return 0;
  }
  else
  {
    $ret = $t->put(String => "areyouthere", Timeout => TIMEOUT, Errmode => "return");
    if($t->timed_out){ $t->close; return 0; }
    
    $ret = $t->get(Timeout => TIMEOUT, Errmode => "return");
    $t->close;
    
    if($t->timed_out)
    { 
      push @OUTPUT, "$host is not available on port $port";
      return 0; 
    }
    
    return 1;
  }
}

# Logs onto machine and executes local watchdog file.
# Pass name of server to log on to.
sub runRemoteWatchdog {
  
  if(! defined $_[0]){ print "Script: Bad usage of sub runRemoteWatchdog!\n"; exit CRITICAL; }
  my $server = $_[0];
  
  if($server =~ /^broadband.mpisws.mlab/)
  {    
    system("timeout 30 ssh $ssh_opt mpisws_broadband\@${server} \"sh install.sh\" >/dev/null 2>/dev/null");
    $? = sprintf("%d", $? >> 8);
    if($? != 0)
    {
      push @OUTPUT, "Cannot logon to $server: $?";
    }
  }
  elsif($server =~ /^loki/)
  {
    system("timeout 30 ssh $ssh_opt root\@${server} \"cd /var/www/bb && sh watchdog-loki.sh\" >/dev/null 2>/dev/null");
    $? = sprintf("%d", $? >> 8);
    if($? != 0)
    {
      push @OUTPUT, "Cannot logon to $server: $?";
    }
  }
  else
  {
    print "From input file $ifile: Unknown server class: $server\n";
    exit CRITICAL;
  }
}

sub hasEnoughDiskSpace {
  
  if(! defined $_[0])
  {
    print "Script: checkRemoteDiskSpace called without parameter.\n";
    exit CRITICAL;
  }
  my $server = $_[0];
  
  # This check is only for MLab nodes
  return 1 unless($server =~ /^broadband.mpisws.mlab/);
  
  $_ = `timeout 30 ssh $ssh_opt mpisws_broadband\@$server "df 2>/dev/null" | grep '/dev'`;
  if(defined $_ && ($_ ne ""))
  {	
    my @df = split;
    if(scalar @df < 4)
    {
      print "Script: Unexpected output of 'df' on $server: $_\n";
      exit CRITICAL;
    }
    my $space =  $df[3]; # Attention, M-Lab df has different output than Debian df
    
    if($space < 1000000)
    {
      push @OUTPUT, "$server runs out of space. Only $space bytes left.";
      return 0;
    }
  }
  else
  {
    push @OUTPUT, "Script: No output of 'df' on $server";
    return 0; # Connection to remote server failed
  }
  
  return 1;
}

sub isWritableDisk {
  
  if(! defined $_[0])
  {
    print "Script: checkRemoteIsWritableDisk called without parameter.\n";
    exit CRITICAL;
  }
  my $server = $_[0];
  
  # This check is only for MLab nodes
  return 1 unless($server =~ /^broadband.mpisws.mlab/);
  
  $_ = `ssh $ssh_opt mpisws_broadband\@$server "touch readOnlyTouchTest.txt 2>&1" | grep 'Read-only file system'`;
  if(defined $_ && ($_ ne ""))
  { 
    push @OUTPUT, "$server is read only.";
    return 0;
  }
  
  return 1;
}


# Send an email to MAINTAINER_EMAIL
# Required parameters: message subject and message body (in this order!)
sub sendWarningEmail {
  
  if(!defined $_[0] || !defined $_[1] || ($_[0] eq '') || ($_[1] eq ''))
  {
    die "Bad usage of sub sendWarningEmail";
  }
  
  my $subject = $_[0];
  my $body = $_[1];
  
  use MIME::Lite; 
  my $msg = MIME::Lite->new( 
    From	=> 'broadband@mpi-sws.mpg.de',
    To	=> MAINTAINER_EMAIL, 
    Subject	=> $subject,
    Data 	=> $body,
  ); 

  $msg->send;
}

