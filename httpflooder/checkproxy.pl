#!/usr/bin/perl
#
# checkproxy.pl
# $Id $
#
# Version: 0.1
# Created: 2013-02-06, Bunyamin Demir
#
# Description: Check Proxy
#
# Release Notes:
#

use strict;
use LWP::UserAgent;
use HTML::Parse;
use Getopt::Long;
use threads;
use threads::shared;
use Time::HiRes qw(gettimeofday tv_interval);
use POSIX qw/ceil/;
use Thread;
use IO::Socket;
use IO::Socket::Socks;
#use IO::Socket::SSL;

my %stats : shared = ();
my $z     : shared = 0;

$stats{code}    = &share({});
$stats{ip_port} = &share({});


my $count : shared = 0;

# Get command-line options
my %opt = (host        => 'www.site.com',
	   proxy_host  => 'www.site.com',
	   proxy_file  => undef,
	   url         => '/',
	   useragent   => 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:8.0) Gecko/20100101 Firefox/8.0',
	   thread      => 1,
	   ssl         => undef,
	   verbose     => 0,
	   poxy_port   => 80,
	   export      => 0,
	   limit       => 0,
	   port        => 80,
	  );

GetOptions('h|host=s'       ,\$opt{host},
	   'ph|phost=s'     ,\$opt{proxy_host},
	   'proxy_file=s'   ,\$opt{proxy_file},
	   'u|url=s'        ,\$opt{url},
	   'p|port=i'       ,\$opt{port},
	   'pp|pport=i'     ,\$opt{proxy_port},
	   'https'          ,\$opt{ssl},
	   'export'         ,\$opt{export},
	   'ua|useragent=s' ,\$opt{useragent},
	   't|thread=i'     ,\$opt{thread},
	   'l|limit=i'      ,\$opt{limit},
	   "v|verbose"      ,\$opt{verbose},
	   "help"           ,sub { &print_usage; exit(0); },
	  );

sub print_usage {

  print qq
    (Check Proxy, v1.0
     Usage: checkproxy.pl [options]
	  [--host]        -h  : Host for HTTP Request
	  [--phost]       -ph : Proxy Host for HTTP Request
	  [--proxy_file]      : Proxy IPs file
	  [--url]         -u  : Request URL
	  [--port]        -p  : Port for HTTP request
	  [--pport]       -pp : Proxy port
	  [--export]          : Write to file
	  [--https]           : SSL support
	  [--useragent]   -ua : User-Agent for HTTP Request Header
	  [--thread]      -t  : Thread number for tool.
	  [--limit]       -l  : Time limit for HTTP response time over proxy.
          [--verbose]     -v  : verbose output
          [--help]            : display usage and options
    );
}

unless ($opt{host}) {
  &print_usage;
  exit(-1);
}

print("+---------------| Check Proxy, v1.0 |-------------+");
print "\r\n";

my $proxies  = &read_files($opt{proxy_file}) if $opt{proxy_file};

my @threads = ();

my $req_per_thread = ceil(scalar(@$proxies) / $opt{thread});


for my $th ( 1 .. $opt{thread}) {
  next unless $proxies->[$th-1];
  my $t = Thread->new(\&requester,\%opt,\%stats,$proxies,$th,$req_per_thread);
  push(@threads,$t);
}

foreach my $t (@threads) {
    my $num = $t->join;
}


&print_stats(\%opt,\%stats);

# --------------------------------------------------------------------------
sub requester {
  my $opt      = shift;
  my $stats    = shift;
  my $proxies  = shift;
  my $thread   = shift;
  my $num      = shift;


  if ($opt{export}) {
    open (FILE, '>>proxies1.txt');
  }

    my $proxy_count = scalar(@$proxies) if $proxies;
    my $socket      = undef;

    foreach my $r (1 .. $num) {
      next unless $proxies->[$count];

      my $proxy    = $proxies->[$count];
      $count++;

      next if $count == $proxy_count;

      my $cbegin = [gettimeofday];

      $proxy =~ /(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})\b/;

      $opt->{proxy_host} = $1;
      $opt->{proxy_port} = $2;

      if ($opt->{ssl}) {
	$socket = &_https_request($opt);
      }
      else {
	$socket = &_http_request($opt);
      }

      next unless $socket;

      $socket->timeout(3);
      print($socket "HEAD $opt->{url} HTTP/1.1\r\n");
      print($socket "Host: $opt->{host}\r\n");
      print($socket "User-Agent:$opt->{useragent}\r\n") if $opt->{useragent};
      print($socket "\r\n");

      my $recv_line = $socket->recv(my $my_message, 12);

      $socket->close();

      my $cend = [gettimeofday];

      my $a= sprintf("%.3f",tv_interval($cbegin,$cend));

      $my_message =~ /(\d{3})/g;

      if ($opt->{export} && ($1 eq '200') &&  ($a <= $opt->{limit})) {
	print FILE "$opt->{proxy_host}:$opt->{proxy_port}\r\n";
      }

      $stats->{code}{"$opt->{proxy_host}:$opt->{proxy_port}"}    = $1;
      $stats->{ip_port}{"$opt->{proxy_host}:$opt->{proxy_port}"} = sprintf("%.3f",tv_interval($cbegin,$cend));

      &_print("c: $count - host: $opt->{host} - url: $opt->{url} - response: $my_message - thread: $thread - time:$a");
      &_print("\r\n");

    }


if ($opt{export}) {
  close (FILE);
}
}

# --------------------------------------------------------------------------

sub _http_request {
  my $opt = shift;

  my $socket = undef;
  #local $SIG{ALRM} = sub { die 'Timed Out'; };

  #eval {
  #  alarm 10;
    $socket = new IO::Socket::INET( PeerAddr => $opt->{proxy_host},
				    PeerPort => $opt->{proxy_port},
				    Proto    => "tcp",
				    Timeout => 3,
				  );
  #  alarm 0;
  #};

  #print "Error: timeout." if ( $@ && $@ =~ /Timed Out/ );
  #print "Error: Eval corrupted: $@" if $@;

#  if ($socket) {
#    $socket->timeout(3);
#  }

  return $socket;

}

# --------------------------------------------------------------------------

sub _https_request {
  my $opt = shift;

  my $socket = new IO::Socket::SSL( PeerAddr        => $opt->{proxy_host},
				    PeerPort        => $opt->{proxy_port},
				    SSL_verify_mode => 'SSL_VERIFY_NONE',
				    Proto           => "tcp"
				  );

  return $socket;

}

# --------------------------------------------------------------------------

sub _print {
  print @_ if $opt{verbose};
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

sub print_stats {
  my $opt = shift;
  my $s   = shift;

  print("\r\n+---------------- Statistics --------------+\r\n");
  #print "IP count: ".scalar(keys %{$s->{ip_port}})." \r\n";

  if ($opt->{export}) {
    open (FILE, '>proxies.txt');
    foreach my $ip_port (sort { $s->{ip_port}->{$a} <=> $s->{ip_port}->{$b} } keys %{$s->{ip_port}}) {
      if($opt->{limit}) {
	next if $s->{code}->{$ip_port} != 200;
	next if $s->{ip_port}->{$ip_port} >= $opt->{limit};
	print FILE "$ip_port\r\n";
	print "$ip_port - $s->{ip_port}->{$ip_port} - $s->{code}->{$ip_port}\r\n";
      }
      else {
	print FILE "$ip_port - $s->{ip_port}->{$ip_port} - $s->{code}->{$ip_port}\r\n";
	print "$ip_port - $s->{ip_port}->{$ip_port} - $s->{code}->{$ip_port}\r\n";
      }
      }
    close (FILE);
  }
  else {
    print "\r\nResponse times\r\n";
    print "-----------------------\r\n";
    foreach my $ip_port (sort { $s->{ip_port}->{$a} <=> $s->{ip_port}->{$b} } keys %{$s->{ip_port}}) {
      if($opt->{limit}) {
	next if $s->{code}->{$ip_port} != 200;
	next if $s->{ip_port}->{$ip_port} >= $opt->{limit};
	print "$ip_port - $s->{ip_port}->{$ip_port} - $s->{code}->{$ip_port}\r\n";
      }
      else {
	print "$ip_port - $s->{ip_port}->{$ip_port} - $s->{code}->{$ip_port}\r\n";
      }
    }
  }
}

# --------------------------------------------------------------------------

1;
