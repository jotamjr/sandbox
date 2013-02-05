#!/usr/bin/perl

# This is a small scripts that attempts to identify if a user exist using the VRFY
# command if the servers allow it
# TOFIX: print help if users doesn't provide the two arguments, check if the SMTP
# server supports the VRFY or EXPN command

use warnings;
use strict;

use Socket;
use Getopt::Long;

my $target='';
my $service='smtp';
my $protocol='tcp';
my $dictionary='';

GetOptions ("host=s" => \$target, "dict=s" => \$dictionary);

open DICT,"<",$dictionary or die "file: $!\n";
print "Brute forcing users from the SMTP server, go for a cup of c8h10n4o2 ;)\n";

my $server=inet_aton $target;
my $port=getservbyname $service,$protocol;
my $buffer='';

while(<DICT>){
    my $user = $_;
    socket(SOCKET, PF_INET, SOCK_STREAM,0) or die "socket: $!\n";
    connect(SOCKET, pack_sockaddr_in($port,$server)) or die "connect: $!\n";
    recv(SOCKET,$buffer,1024,0);
    send(SOCKET,"VRFY $user\r\n",0);
    recv(SOCKET,$buffer,1024,0);
    if($buffer =~ m/(^250\s.*)|(^252\s.*)/){
        print "found user $user";
        #print $buffer; #To log server output remove the # at the ^ of this line
    }
    send(SOCKET,"QUIT\r\n",0);
    close(SOCKET);
}
close(DICT);
