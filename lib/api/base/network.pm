#
# api::base::network.pm
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

package api::base::network;

##########################################################################################

use strict;
use warnings;

##########################################################################################

use Fcntl;
use Socket;
use Socket6;

##########################################################################################

#
# Module constructor
#
#  This function is called in order to create
#  API base module instance. 
#
#   Input:	1. class name (passed implicitly)
#
#   Output:	1. api::base object reference
#
sub new($) {
    my $class = shift;

    my $self = {};

    return bless($self, $class);
}
#
# Set nonblocking mode on a file handle.
#
#   Input:	1. self object reference
#		2. file handle
#
#   Output:	1. TRUE on success,
#		   FALSE otherwise
#
sub set_nonblocking($$) {
    my ($self, $fh) = @_;
    my $flags = fcntl($fh, &F_GETFL, 0);
    return fcntl($fh, &F_SETFL, $flags | &O_NONBLOCK);
}
#
# Check if given string is an IPv4 address or prefix
#
#   Input:	1. self object reference
#		2. address string
#
#   Output:	1. TRUE on match,
#		   FALSE otherwise
#
sub is_ipv4($$) {
    return (defined($_[1]) && $_[1] =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d{1,2})?$/) ? 1:0;
}
#
# Check if given string is an IPv6 address or prefix
#
#   Input:	1. self object reference
#		2. address string
#
#   Output:	1. TRUE on match,
#		   FALSE otherwise
#
sub is_ipv6($$) {
    return (defined($_[1]) && $_[1] =~ /^[a-fA-F\d]{0,4}(?:\:(?!\:\:)[a-fA-F\d]{1,4}){0,6}(?:\:\:)?(?:[a-fA-F\d]{1,4}\:(?!\:\:)){0,6}[a-fA-F\d]{0,4}(?:\/\d{1,2})?$/) ? 1:0;
}
#
# Do a quick and dirty hostname resolving
#
#   Input:	1. self object reference
#		2. host
#		3. optional address family (ipv4 or ipv6)
#
#   Output:	1. if given host was a hostname,
#		   IP address of the host; otherwise
#		   the same string that was passed.
#
#		on failure: undef
#
sub get_host_by_name($$;$) {
    my ($self, $host, $af) = @_;

    if($self->is_ipv4($host)) {
	# If address family isn't explicitly defined
	# or IPv4 is requested, return IPv4 address
	return (!defined($af) || $af eq 'ipv4') ? $host:undef;
    }elsif($self->is_ipv6($host)) {
	# If address family isn't explicitly defined
	# or IPv6 is requested, return IPv6 address
	return (!defined($af) || $af eq 'ipv6') ? $host:undef;
    } else {
	# Unless defined otherwise, prefer IPv6 addresses
	if((!defined($af) || $af eq 'ipv6')) {
	    # Get IPv6 address
	    my @a = getaddrinfo($host, 0, AF_INET6);
	    if(scalar(@a) > 0 && defined($a[3]) && $a[3] ne '') {
		my ($ipv6) = getnameinfo($a[3], NI_NUMERICHOST);
		return $ipv6 if($self->is_ipv6($ipv6));
	    }
	}
	# If IPv4 was requested or IPv6 address is missing,
	# resolve into IPv4 addresses
	if((!defined($af) || $af eq 'ipv4')) {
	    # Get IPv4 address
	    my @a = getaddrinfo($host, 0, AF_INET);
	    if(scalar(@a) > 0 && defined($a[3]) && $a[3] ne '') {
		my ($ipv4) = getnameinfo($a[3], NI_NUMERICHOST);
		return $ipv4 if($self->is_ipv4($ipv4));
	    }
	}
    }

    return undef;
}
#
# Get local IP addresses.
#
#  This method retrieves (IPv4, IPv6 or both) addresses from
#  local network interfaces, either explicitly specified or
#  assumed.

#  If network interface was not explicitly specified, method
#  will assume the interface that the default route points to.
#  Note that different address families can have different
#  default interfaces.
#
#  If address family was specified as 'any' or wasn't specified
#  at all, return values in list context will contain both
#  IPv4 and IPv6 addresses. Also, IPv4 addresses are retrieved
#  first, so in the scalar context an IPv4 address will be
#  returned unless IPv4 address is missing from the interface.
#
#   Input:		1. self object reference
#			2. optional interface
#			3. optional address family ('ipv4','ipv6' or 'any')
#
#   Output:		1. (scalar context) first retrieved IP address
#			   (list context) array of retrieved IP addresses
#
sub get_local_addr($;$$) {
    my ($self, $iface, $af) = @_;

    my @addrs = ();

    # If IPv4 or no explixit address family was requested ...
    if(!defined($af) || $af eq 'ipv4' || $af eq 'any') {
	# ... get the default gateway from IPv4 routing table
	my ($ipv4_iface) = (defined($iface) && $iface ne "") ?
				($iface):(`route -n` =~ /0\.0\.0\.0\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+0\.0\.0\.0\s+[a-zA-Z]+\s+\d+\s+\d+\s+\d+\s+([^\s\n]+)/g);
	if(defined($ipv4_iface) && $ipv4_iface ne "") {
	    my $ifconfig = `ifconfig $ipv4_iface`;
	    # ... get the IPv4 address of the interface facing the default gateway
	    my ($ipv4_addr) = ($ifconfig =~ /\n\s+inet\s+addr:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+/i);
	    # ... and if we have a valid IPv4 address ...
	    if(defined($ipv4_addr) && $ipv4_addr ne "") {
		# ... put it into the list
		push @addrs, $ipv4_addr;
	    }
	}
    }

    # If IPv6 or no explixit address family was requested ...
    if(!defined($af) || $af eq 'ipv6' | $af eq 'any') {
	# ... get the default gateway from IPv6 routing table
	my ($ipv6_iface) = (defined($iface) && $iface ne "") ?
				($iface):(`route -n -Ainet6` =~ /\:\:\/0\s+[a-fA-F\d]{0,4}(?:\:(?!\:\:)[a-fA-F\d]{1,4}){0,6}(?:\:\:)?(?:[a-fA-F\d]{1,4}\:(?!\:\:)){0,6}[a-fA-F\d]{0,4}\s+[a-zA-Z]+\s+\d+\s+\d+\s+\d+\s+([^\s\n]+)/g);
	if(defined($ipv6_iface) && $ipv6_iface ne "") {
	    my $ifconfig = `ifconfig $ipv6_iface`;
	    # ... get the IPv6 addresses of the interface facing the default gateway
	    while($ifconfig =~ /\n\s+inet6\s+addr:\s*([a-fA-F\d]{0,4}(?:\:(?!\:\:)[a-fA-F\d]{1,4}){0,6}(?:\:\:)?(?:[a-fA-F\d]{1,4}\:(?!\:\:)){0,6}[a-fA-F\d]{0,4})\/\d+\s+Scope:(?:Global|Host)/ig) {
		# Put IPv6 address into the list
		push @addrs, $1;
	    }
	}
    }

    # In list context, return all found local addresses
    # In scalar context, return the first found address
    return wantarray ? (@addrs):$addrs[0];
}

1;
