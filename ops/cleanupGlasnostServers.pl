#!/usr/bin/perl

# This is a mainenance script for Measurement Lab.
# This script removes already fetched log files from the nodes
# Added by Marcel Dischinger
#
# Usage: Pass path to file with server names (measurement-servers.php).
#        Lines that start with a # are ignored
#
# The script currently only supports servers from Measurement Lab and
# ignores servers from other locations.

use strict;

# SSH options
my $key = '-i /DS/home-0/mdischin/.ssh/md_ext_key -i /DS/home-0/mdischin/.ssh/id_dsa_pl';
my $ssh_opt = "$key -o ConnectTimeout=30 -o StrictHostKeyChecking=no";


# NAGIOS return values
use constant OK => 0;
use constant WARNING => 1;
use constant CRITICAL => 2;
use constant UNKNOWN => 3;

my $ifile = shift;
if(! -s $ifile)
{
  print "Script parameter: $ifile not found.";
  exit CRITICAL;
}

my @OUTPUT;


open(SERVERS, $ifile);
while(<SERVERS>)
{
  chomp;
  my $server;
  
  # Parse measurement-servers.php file
  if(/^[\s\t]*#/){ next; }
  
  if(/\'.+\'/)
  {
    my @l = split(/'/);
    
    next if(scalar @l < 2);
    $server = $l[1];
    
    if($server =~ /^broadband.mpisws.mlab/)
    {
      $server = substr($server, 17);
    }
  }
  else { next; }
  
        
  if($server =~ /^mlab/)
  {
    my @t = split(/\./, $server);
    my $s = "$t[0].$t[1]";

    system("ssh $ssh_opt mpisws_broadband\@${server} \"cd logs && perl ../cleanup.pl ../${s}.removal\" >/dev/null 2>/dev/null");
    $? = sprintf("%d", $? >> 8);
    if($? != 0)
    {
      push @OUTPUT, "Cannot logon to $server: $?";
    }
  }
  elsif($server =~ /^loki/)
  {
    my @t = split(/\./, $server);
    my $s = $t[0];
    
    system("ssh $ssh_opt root\@${server} \"cd /var/www/bb/logs/ && perl ~/cleanup.pl ~/${s}.removal\" >/dev/null 2>/dev/null");
    if($? != 0)
    {
      push @OUTPUT, "Cannot logon to $server.";
    }
  }
  else
  {
    print "Script: Unknown server class: $server";
    exit CRITICAL;
  }
}
close(SERVERS);

foreach my $line (@OUTPUT){
  print "$line\n";
}

if(scalar @OUTPUT > 0)
{
  exit WARNING;
}

exit OK;
