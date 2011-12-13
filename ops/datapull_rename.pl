#!/usr/bin/perl

# This script is used to move the Glasnost log files to the data sink
# (or "dropbox") M-Lab uses to archive log files.

# Attention: Files get renamed to the M-Lab format

use strict;
use Sys::Hostname;

my $path = "/home/mpisws_broadband/glasnost/";

# M-Lab file format:
#<tool>/YYYY/MM/DD/<server_hostname>/
#<iso8601date>_<client_ipaddress>_[<client_hostname>[:<port>]].<suffix>[.<gz>]

my $servername = hostname;

my $now = time;
my $back = $now - 60*60; # go 1 hour back    

chdir("logs");
while(<*>)
{
  next unless(/^bt_/ || /^glasnost_/);
  
  my $fname = $_;
  
  my @l = split('_');
  
  # /bt_88.147.43.208_88.147.43.208_1214660901.dump.gz
  my $ts = $l[$#l];
  my $ip = $l[1];
  my $hname = $l[2];
  for(my $i=3; $i< $#l; $i++) # There might be underscores in the hostname
  {
    $hname .= "_$l[$i]";
  }
     
  my $suffix;
  if($ts =~ /dump.gz$/)
  {
    chop($ts);chop($ts);chop($ts);chop($ts);
    chop($ts);chop($ts);chop($ts);chop($ts);
    $suffix = "dump.gz";
  }
  else
  {
    chop($ts);chop($ts);chop($ts);chop($ts);
    $suffix = "log";
  }
  
  next if($ts >= $back);
  
  my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = gmtime($ts);
  $year += 1900;
  $mon++;
  
  if($mon < 10){ $mon = "0$mon"; }
  if($mday < 10){ $mday = "0$mday"; }
  if($hour < 10){ $hour = "0$hour"; }
  if($min < 10){ $min = "0$min"; }
  if($sec < 10){ $sec = "0$sec"; }
  
  my $date = "${year}-${mon}-${mday}T${hour}:${min}:${sec}";
  
  # Build path
  my $mvpath = "$path/$year/$mon/$mday/$servername/${date}_${ip}_${hname}.$suffix";
  
  if(! -d "$path/$year/$mon/$mday/$servername/")
  {
    system("mkdir -p $path/$year/$mon/$mday/$servername/");
  }
  
  system("cp $fname $mvpath");
}


# Now cleanup old data
my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = gmtime($now);
$mon++; # Jan=0 in gmtime, but 01 for directory name
$mday++; # Month count starts with 0 in perl

chdir($path);
while(<*>)
{
  next unless(-d);
  my $y = $_;
  
  # Remove year folder if it is the last year and at least one month has passed
  if(($y < $year) && ($mon >= 1))
  {
    system("rm -rf $y");
    next;
  }
      
  chdir($y);
  while(<*>)
  {
    my $m = $_;
    
    if($m < ($mon-1)) # Delete data that is older than 2 months
    {
      system("rm -rf $m");
      next;
    }
    elsif($m == ($mon-1)) # Delete data that is older than 5 days
    {
      my $xday = $mday + 28;
      
      chdir($m);
      while(<*>)
      {
	if($_+5 < $xday)
	{
	  system("rm -rf $_");
	}
      }
      chdir("..");
    }
    elsif($m == $mon) # Delete data that is older than 5 days
    {
      chdir($m);
      while(<*>)
      {
	if($_+5 < $mday)
	{
	  system("rm -rf $_");
	}
      }
      chdir("..");
    }
  }  
  chdir("..");
}
