#
# api::base::logger.pm
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

package api::base::logger;

##########################################################################################

use strict;
use warnings;

##########################################################################################

use Sys::Syslog;

##########################################################################################

#
# Module constructor
#
#  This function is called in order to create
#  API base module instance.
#
#   Input:	1. class name (passed implicitly)
#
#   Output:	1. api::logger object reference
#
sub new($) {
    my $class = shift;

    my $self = {};

    return bless($self, $class);
}
#
# Issue conditional syslog call
#
#  This function check if given log level is less or equal
#  to configured max. log level and only then issues syslog()
#  call.
#
#   Input:	1.self object reference
#		2.log level
# 		3.format string
#		+ variable number of arguments
#
#   Output:	nothing
#
sub logging($$;@) {
    my $self = shift;
    my $loglevel = shift;
    my @SYSLOG_LEVELS = ('LOG_EMERG','LOG_ALERT','LOG_CRIT','LOG_ERR','LOG_WARNING','LOG_NOTICE','LOG_INFO','LOG_DEBUG');
    my $i;
    for($i = 0; $i < $#SYSLOG_LEVELS+1; $i++) {
	last if($SYSLOG_LEVELS[$i] eq $loglevel);
    }

    for(; $i < $#SYSLOG_LEVELS+1; $i++) {
	if($SYSLOG_LEVELS[$i] eq $self->{'syslog_level'}) {
	    if($self->{'log_to_syslog'}) {
		syslog($loglevel, @_);
	    }
	    if($self->{'log_to_console'} && $self->{'foreground'}) {
		my $fmt = shift(@_);
		my ($level) = ($loglevel =~ /^LOG\_(.+)$/);
		printf(STDERR "[".$level."] ".$fmt."\n", @_);
	    }
	    last;
	}
    }
}

1;
