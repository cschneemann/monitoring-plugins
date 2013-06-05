#!/usr/bin/perl
#
# check_unix_users_open_files.pl - nagios plugin
#
# Copyright (C) 2013 B1 Systems GmbH <info@b1-systems.de>,
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
#
#
## purpose: This Nagios Plugin checks the open filedescriptors of a user
## author: Christian Schneemann <schneemann@b1-systems.de>, 2013.

use strict;
use warnings;

use Nagios::Plugin;

my $VERSION = "1.0.0";

my $np = Nagios::Plugin->new(
    usage => "Usage: %s [ -v|--verbose ]  -u <user> [ -c|--critical=<critical threshold> ] [ -w|--warning=<warning threshold> ]  ",
    version => $VERSION,
    shortname => "check_unix_users_ofds",
    blurb   => "This Plugin checks the opened filedscriptors of a user on unix/linux.",
#    extra   => $extra,
#    url     => $url,
    license => "GPLv2",
#    plugin  => basename $0,
    timeout => 15,
);

$np->add_arg(
    spec => 'user|u=s',
    help => "--user, -u\n   name of the user",
    required => 1,
    );

$np->add_arg(
    spec => 'warning|w=s',
    help => "--warning, -w \n   % of ulimit -n",
    required => 0,
    );

$np->add_arg(
    spec => 'critical|c=s',
    help => "--critical, -c\n   % of ulimit -n",
    required => 0,
    );


$np->getopts;

my $rc = "OK";

my $username = $np->opts->get('user');

if (`/usr/bin/id $username 2>&1` =~ /No such user/) {
  $np->nagios_exit( UNKNOWN, "user $username does not exist");
}

my $max_allowed_handles = qx(echo `ulimit -n`);
# use ulimit -Hn for hardlimit (may be higher)
chomp $max_allowed_handles;

my ($warning, $critical);

if (defined($np->opts->get('warning'))) {
  $warning = $max_allowed_handles/100*$np->opts->get('warning');
}
if (defined($np->opts->get('critical'))) {
  $critical = $max_allowed_handles/100*$np->opts->get('critical');
}


my @lsof = split('\n',`/usr/bin/lsof -u $username`);
shift @lsof;
my %open_handles;

foreach my $pid ( map{(split(/\s+/, $_))[1]} @lsof) {
  $open_handles{$pid}++;
}

my $max_handles = 0;
my $max_handles_pid;

foreach my $pid (keys %open_handles) {
  if ($open_handles{$pid} > $max_handles ) {
    $max_handles = $open_handles{$pid};
    $max_handles_pid = $pid;
  }
}

my $check = $np->check_threshold(check => $max_handles,
                                 warning => $warning,
                                 critical => $critical
                                );
$np->add_perfdata( label => 'max open files per proc',
                   value => $max_handles,
                   warning => $warning,
                   critical => $critical,
                   min => 0,
                   max => $max_allowed_handles
                  );

if ($check == 1) {
  $rc = "WARNING";
} elsif ($check == 2) {
  $rc = "CRITICAL";
} 

$np->nagios_exit( $rc, "PID $max_handles_pid of user $username has $max_handles open files");

