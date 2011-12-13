#!/usr/bin/perl

use strict;

while(<*>){
  chomp;

  my $file = $_;

  my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,
      $atime,$mtime,$ctime,$blksize,$blocks) = stat $file;

  # File was not modified within the past 6 hours, so delete it
  if(($mtime + 144000) < time){
    unlink($file);
#    printf "$_ is %.1f days old\n", (time-$mtime)/86400;
  }


} close IN;
