#
# api::base.pm
#
# Copyright (c) 2014 Marko Dinic <marko@yu.net>. All rights reserved.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

package api::base;

##########################################################################################

use strict;
use warnings;

##########################################################################################

use Socket;
use IO::Handle;
use Sys::Syslog;
use POSIX qw(:signal_h :sys_wait_h);

##########################################################################################

use api::base::network;
use api::base::logger;

##########################################################################################

our @ISA = qw(
    api::base::network
    api::base::logger
);

##########################################################################################

our $ARG_DELIMITER = chr(255);

our $AUTOLOAD;

##########################################################################################

#
# Module constructor
#
#  This function is called in order to create
#  API base module instance. It takes a hashref
#  to the global OpenLB configuration and blesses
#  it into an object of api::base class. This
#  makes it easy for OpenLB modules to access
#  global configuration directly, and each others'
#  by obtaining module object references by name.
#
#   Input:	1. class name (passed implicitly)
#		2. hashref to the global configuration
#
#   Output:	1. api::base object reference
#
sub new($$) {
    my ($class, $conf) = @_;

    bless($conf, $class);

    openlog($conf->get_progname(), "nodelay,pid", $conf->{'syslog_facility'});

    return $conf;
}
#
# Serialize and put input data.
#
#  This function 'packs' an array of input data fields
#  into a string and writes it to the specified channel.
#
#   Input:	1. self object reference
#		2. output file handle
#		3. arrayref to data,
#		   or array of data fields
#
#   Output:	nothing
#
sub put_args($$;@) {
    my $self = shift;
    my $channel = shift;

    return unless(defined($channel) && defined($_[0]));

    # Write serialized data fields array
    # to the output file handle
    print $channel join($ARG_DELIMITER, ((ref($_[0]) eq 'ARRAY') ? (@{$_[0]}):(@_)))."\n";
    $channel->flush();
}
#
# Get and un-serialize input data.
#
#  This function reads a single line from the input channel
#  and 'unpacks' data fields from it, returning them either
#  as an array or a reference to that same array.
#
#   Input:	1. self object reference
#		2. input file handle
#
#   Output:	1. (list context) array of data fields
#		   (scalar context) arrayref to data
#		   undef, if failed
#
sub get_args($$) {
    my $self = shift;
    my $channel = shift;

    unless(defined($channel)) {
	return wantarray ? ():undef;
    }

    # Read a line from input channel
    my $line = <$channel>;
    unless(defined($line) && $line ne '') {
	return wantarray ? ():undef;
    }

    # Remove trailing newline
    chop $line;

    unless($line ne '') {
	return wantarray ? ():undef;
    }

    # Split line into data fields
    my @argv = split(/$ARG_DELIMITER/, $line);

    # Return complete array
    return wantarray ? (@argv):\@argv;
}
#
# Proxy function calls to the main program.
#
#  Purpose of this function is to provide modules 
#  the clean way of accessing functions defined
#  inside the main code. After creating an instance
#  of this module, any $api->function(...) call
#  that doesn't find a function in this module
#  will be proxied to &main::function(...).
#
sub AUTOLOAD {
    my $self = shift;
    my $res;

    # Unqualify function name
    my ($func_name) = ($AUTOLOAD =~ /^(?:.*::)?([^:]+)/);
    unless(defined($func_name) && $func_name ne "") {
	$self->logging('LOG_ERR', "Invalid function %s called by %s",
				  $func_name,
				  caller());
	return undef;
    }

    # Wrap the call inside eval to gracefully
    # catch errorneous function calls.
    eval {
	# Disable strict references locally
	no strict qw(refs);
	# Call the function inside the main context
	$res = &{'main::__'.$func_name}(@_);
    };

    if($@) {
	$self->logging('LOG_ERR', "Function %s called by %s is not defined by OpenLB API",
				  $func_name,
				  caller());
	return undef;
    }

    return $res;
}
#
# Module destructor
#
#  This function is automatically called
#  when module is unloaded.
#
sub DESTROY {
    closelog();
}

1;
