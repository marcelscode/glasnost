# This script looks for Glasnost log files in all sub-directories.
# It extracts a short summary from the log file (i.e., the same data
# the Glasnost webpage uses for traffic shaping detection) and outputs
# it (each line one test run).
# The resulting output can then be fed into glasnost_differentiation_detector.pl

# You can optionally pass a file that contains the output of a previous run. The
# script will then skip files with logs from already processed tests.

# Usage: perl generate_summary2.pl > glasnost.sum

# STDERR contains info about failed tests. You can savely redirect STDERR to /dev/null

# NOTE: The function processFile() needs adjustment as it expects a particular file 
# name scheme that is not the same as for the MLab-rsynced data. 

# Written by Marcel Dischinger, MPI-SWS 2009
# License: CC BY-SA 3.0 (http://creativecommons.org/licenses/by-sa/3.0/)

use strict;

my %done;

######### Speedup ##########

# If a file was passed as a parameter, save log file name to hash
# and later skip these files from extraction.
open SUM, shift;
while(<SUM>){
  chomp;
  my @line = split(';');

  # if($line[@line-1] =~ /ZZZ/){ delete $line[@line-1]; }

  $done{"$line[@line-1]"} = 1;
}
close SUM;

############################


while(<*>){

  # Find directories that are accessible
  next unless(-d $_ && -x $_);

  my $dir = $_;
  chdir($_);
  #print "Processing $dir\n";

  # Read files from directory and process
  while(<*>){
    processFile($_, $dir);
  }
  chdir("..");
}


############ Functions ##################

sub processFile{
  $_ = $_[0];
  my $dir = $_[1];

  my $type;
  # Only use files with the Glasnost-specific log file name
  if(/^glasnost_.+\.log/){ $type = 'glasnost'; }
  else { next; }
  
  # Glasnost has two log files per test run:
  # A log file and a gzipped pcap file
  # $file holds the log file, in $dump we generate
  # the name for the pcap file.
  # If not both are present, we skip as the test data
  # is not complete.
  
  my $file = $_;

  next if(defined $done{$file});

  my $dump = $_;
  chop($dump); chop($dump); chop($dump);
  $dump .= "dump.gz";

  if(! -e $dump){
	print STDERR "Cannot find ${dir}/${dump}\n";
	next;
  }

  my $res = parseFile($file, $dir);

  if($res != -1 && $res != -2){
    print "$res;$dir;$file\n";
  }
}

sub parseFile{
  my $filename = $_[0];
  my $dir = $_[1];
  
  my $start = -1; 
  my ($hostname, $ip, $client, $server, $done);
  
  my $num_flows = 0;
  my $proto;
  
  open LOG, $filename or die $!;
  while(<LOG>){
    chomp;

    # Get IP, hostname, and starttime (unix timestamp) of test run
    if(($start == -1) && (/^(\d{13}) Client (.+) (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) connect/)){
      $start = $1;
      $hostname = $2;
      $ip = $3;
    }
    else
    {      
      # Get client-side compressed log data
      if(/^\d{13} Client: http (.+)$/){
	$client = $1;
      }
      # Get server-side compressed log data
      elsif(/^\d{13} http (.+)$/){
	$server = $1;
      }
      # This line indicates that the test ran to the end
      elsif(defined $client && defined $server && /^\d{13} Done.$/){
	$done = 1;
      }
      # Collect some statistics for failed tests
      elsif(/^\d Received/){
	$num_flows ++;
	
	if(! defined $proto && /^\d Received: replay (.+) as/){
	  $proto = $1;
	}
      }
    }
  }
  close LOG;
  
  if($start == -1){ print STDERR "NoStart "; }
  elsif(! defined $client){ print STDERR "NoClient "; }
  elsif(! defined $server){ print STDERR "NoServer "; }
  
  
  if((! defined $client && ! defined $server) || ($start == -1) || (! defined $done)){
    print STDERR "flows=$num_flows proto=\"$proto\" ";
    print STDERR "Parser failed for $dir/$filename\n";
    return -1;
  }
  elsif(! defined $client || ! defined $server){
    print STDERR "flows=$num_flows proto=\"$proto\" ";
    print STDERR "Data not complete for $dir/$filename\n";
    return -2;
  }
  
  return "${start};${ip};${hostname};${client};${server}";
}

###############################################################3
