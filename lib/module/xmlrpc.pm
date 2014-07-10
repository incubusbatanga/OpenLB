#
# module::xmlrpc.pm
#
# Copyright (c) 2014 Marko Dinic <marko@yu.net>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.
#

package module::xmlrpc;

##############################################################################################

use strict;
use warnings;

##############################################################################################

use XML::RPC;
use Config::ContextSensitive qw(:macros);

##############################################################################################

use api::module;

##############################################################################################

our @ISA = qw(api::module);

##############################################################################################

my $CONF_TEMPLATE = SECTION(
    DIRECTIVE('check_interval', ARG(CF_INTEGER, STORE(TO 'MODULE', KEY { '$SECTION' => { 'check_interval' => '$VALUE' } }), DEFAULT '0')),
    DIRECTIVE('rpc_timeout', ARG(CF_INTEGER, STORE(TO 'MODULE', KEY { '$SECTION' => { 'rpc_timeout' => '$VALUE' } }), DEFAULT '3')),
    DIRECTIVE('rpc_url', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$SECTION' => { 'rpc_url' => '$VALUE' } }))),
    DIRECTIVE('rpc_call', ARG(CF_ARRAY, STORE(TO 'MODULE', KEY { '$SECTION' => { 'rpc_call' => '$VALUE' } }))),
    DIRECTIVE('user_agent', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$SECTION' => { 'user_agent' => '$VALUE' } }), DEFAULT 'Mozilla/3.0')),
    DIRECTIVE('username', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$SECTION' => { 'username' => '$VALUE' } }))),
    DIRECTIVE('password', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$SECTION' => { 'password' => '$VALUE' } }))),
    DIRECTIVE('field', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$SECTION' => { 'fields' => ['$VALUE'] } })))
);

##############################################################################################

sub register() {
    return $CONF_TEMPLATE;
}

sub daemonize($) {
    my $self = shift;

    my $instdata = {};

    # Set initial timeout for initialize()
    $self->set_initialize_timeout($self->{'rpc_timeout'});

    return $instdata;
}

sub initialize($$) {
    my ($self, $instdata) = @_;

    # Initialize modules and data we use
    return $self->reinitialize($instdata);
}

sub reinitialize($$) {
    my ($self, $instdata) = @_;

    # Set our own timeout which will take
    # effect on our next invocation
    $self->set_reinitialize_timeout($self->{'rpc_timeout'});

    # Create XML-RPC user agent
    my $ua = XML::RPC::UA::LWP->new(timeout => $self->{'rpc_timeout'},
				    ua => $self->{'user_agent'});
    return undef unless defined($ua);

    # Create XML-RPC client
    my $rpc = XML::RPC::Fast->new($self->{'rpc_url'}, ua => $ua);
    return undef unless defined($rpc);

    # Store client in our runtime data store
    $instdata->{'rpc'} = $rpc;

    # Cleanup runtime data and events
    $self->cleanup($instdata);

    # This module can be used either as input or
    # output module for a load balancer, but never
    # both at the same time. If xmlrpc is required
    # as both input and output, multiple instances
    # of this module must be used.

    # If check interval is 0, no collection will
    # occur, thus disabling input and enabling
    # output operation mode. Configuring either
    # input or output load balancer role with
    # wrong operation mode will result in noop.
    if($self->{'check_interval'} <= 0) {
	# This is where reinitialize ends
	# in the output operation mode
	return $instdata;
    }

    # Create/modify data collector
    $instdata->{'collector'} = defined($instdata->{'collector'}) ?
					$self->api->modify_timer_event($instdata->{'collector'},
								       'args' => [ $self, $instdata ],
								       'interval' => $self->{'check_interval'},
								       'timeout' => $self->{'rpc_timeout'} + 1):
					$self->api->create_timer_event('interval' => $self->{'check_interval'},
								       'handler' => \&collect,
								       'args' => [ $self, $instdata ],
								       'timeout' => $self->{'rpc_timeout'} + 1,
								       'on_timeout' => \&collect_timeout);

    return $instdata;
}

sub cleanup($$) {
    my ($self, $instdata) = @_;

    # If collector was previosly running ...
    if(defined($instdata->{'collector'})) {
	# ... stop it
	$self->api->destroy_timer_event($instdata->{'collector'});
    }

    # Clean up reconfigurable runtime data
    delete $instdata->{'collector'};
    delete $instdata->{'rpc_call'};
    delete $instdata->{'params'};
}

sub host($$;$) {
    my ($self, $instdata, $address_family) = @_;

    return wantarray ?
		($instdata->{'ipv4'}, $instdata->{'ipv6'}):
		(defined($address_family) ?
		    $instdata->{$address_family}:
		    (defined($instdata->{'ipv6'}) ?
			$instdata->{'ipv6'}:
			$instdata->{'ipv4'}));
}

##############################################################################################

sub process($$$$$$$$) {
    my ($self, $instdata, $lb, $seq, $preference, $input, $ipv4, $ipv6) = @_;

    # If check interval is above 0, instance is
    # operating as a collector (input mode) and
    # cannot process output data.
    if($self->{'check_interval'} > 0) {
	# Make a note in the log
	$self->api->logging('LOG_WARNING', "cURL collector %s dropping data received from load balancer %s",
					   $self->{'instance'},
					   $lb);
	return;
    }

    # Prefer IPv6 over IPv4
    my $host = (defined($ipv6) && $ipv6 ne '') ? $ipv6:$ipv4;

    # We must have the device IP in order
    # for update to make any sense ...
    return unless(defined($preference) && $preference ne '' &&
		  defined($host) && $host ne '');

    # Map variable names to dataset columns
    $instdata->{'params'} = {
	'lb'		=> defined($lb) ? $lb:'',
	'seq'		=> defined($seq) ? $seq:'',
	'input'		=> defined($input) ? $input:'',
	'ipv4'		=> defined($ipv4) ? $ipv4:'',
	'ipv6'		=> defined($ipv6) ? $ipv6:'',
	'host'		=> $host,
	'preference'	=> $preference
    };

    # If RPC method's arguments are defined ...
    if(defined($self->{'rpc_call'})) {
	# Substitute variable names with values
	# in RPC method's argument list
	foreach my $arg (@{$self->{'rpc_call'}}) {
	    # xlat argument
	    my $xarg = $self->xlat($arg, $instdata);
	    # Store xlated argument
	    push @{$instdata->{'rpc_call'}}, defined($xarg) ? $xarg:'';
	}
    }

    # Update the target with data
    # received from load balancer
    eval {
	$instdata->{'rpc'}->call(@{$instdata->{'rpc_call'}});
    };
    # Check if request failed
    if($@) {
	# Make a note in the log
	$self->api->logging('LOG_ERR', "cURL backend %s failed to update resource %s",
				       $self->{'instance'},
				       $self->{'request_url'});
    }

    return;
}

sub process_timeout($$) {
    my ($self, $instdata) = @_;

    $self->api->logging('LOG_WARNING', "cURL backend %s: update request timed out",
				       $self->{'instance'});
}

##############################################################################################

sub collect($$$) {
    my ($event, $instance, $instdata) = @_;

    # Resolve the host part of the URL
    my ($host) = ($instance->{'request_url'} =~ /^[a-zA-Z]+:\/\/([^\/:]+)/);
    $instdata->{'ipv4'} = $instance->api->get_host_by_name($host, 'ipv4');
    $instdata->{'ipv6'} = $instance->api->get_host_by_name($host, 'ipv6');

    # Host-part of the URL must resolve to something
    my @addr = ($instdata->{'ipv6'}, $instdata->{'ipv4'});
    shift @addr unless defined($addr[0]);
    pop @addr unless defined($addr[$#addr]);

    if(scalar(@addr) < 1) {
	# Notify the load balancer the host is down
	$instance->api->logging('LOG_INFO', "cURL collector %s down",
					    $instance->{'instance'});
	return $instance->down;
    }

    my @values;
    
    # Update the target with data
    # received from load balancer
    eval {
	@values = $instdata->{'rpc'}->call(@{$self->{'rpc_call'}});
    };
    # Check if request failed
    if($@) {
	# Notify the load balancer the host is down
	$instance->api->logging('LOG_INFO', "cURL collector %s down",
					    $instance->{'instance'});
	return $instance->down;
    }

    if(scalar(@values) > 0) {
	# Send serialized collected data to the load balancer
	$instance->api->logging('LOG_INFO', "cURL collector %s: host %s up: ".join('=%s, ', @{$instance->{'fields'}})."=%s",
					    $instance->{'instance'},
					    join(', ', @addr),
					    @values);

	return $instance->up(@values);
    }

    # Notify the load balancer the host is down
    $instance->api->logging('LOG_INFO', "cURL collector %s: host %s down: failed to collect data",
					$instance->{'instance'},
					join(', ', @addr));

    return $instance->down;
}

sub collect_timeout($$$) {
    my ($event, $instance, $instdata) = @_;

    # Notify the load balancer the host is down
    $instance->api->logging('LOG_INFO', "cURL collector %s down: timed out",
				        $instance->{'instance'});

    return $instance->down;
}

##############################################################################################

#
# Retrieve data from or send data to the specified URL
#
#  This method performs high level handling of requests.
#  It is ment to be the frontend method for all network
#  communication for the rest of the code.
#
#   Input:	1. self object reference
#		2. instance data hashref
#
#   Output:	1. HTTP::Response object
#		   undef, if failed
#
sub curl($$) {
    my ($self, $instdata) = @_;

    # Request the document
    my $res = $self->request($instdata);
    return undef unless defined($res);

    # Authentication is required ?
    if($res->code() == 401) {
	# Extract realm name from the response header
	my $auth_header = $res->header('WWW-Authenticate');
	my ($realm) = ($auth_header =~ /realm=\"([^\"]*)\"/i);
	# If username and password are defined,
	# put them into user agent's keyring.
	# This needs to be done only once.
	# Subsequent requests will not fail with
	# 401 code, since the credentials stay
	# in the keyring.
	if(defined($self->{'username'}) &&
	   defined($self->{'password'})) {
	    # Extract protocol, address and port
	    # of the monitored host from URL
	    my ($proto, $host, $port) = ($self->{'request_url'} =~ /^([a-zA-Z]+):\/\/([^\/:]+)(?::(\d+)|\/)?/);
	    # Format address:port for credentials(...) call
	    my $address = $host.":".(defined($port) ?
					$port:getservbyname('tcp', $proto));
	    # Prepare credentials
	    $instdata->{'ua'}->credentials(
		$address,
		$realm,
		$self->{'username'},
		$self->{'password'}
	    );
	    # Request the document again
	    $res = $self->request($instdata);
	}
    }

    return $res;
}
#
# Perform the request
#
#  This method performs low level handling of requests.
#  It performs the request via user-selected request
#  method. Supported request methods are:
#
#    GET, POST, PUT, DELETE
#
#  Form fields and request data are used, if defined.
#  GET and DELETE methods encode form fields in the
#  URL itself, while POST and PUT methods pass form
#  data in the request's body.
#
#   Input:	1. self object reference
#		2. instance data hashref
#
#   Output:	1. HTTP::Response object
#		   undef, if failed
#
sub request($$;$$) {
    my ($self, $instdata) = @_;

    # If request data is defined, we want to send it
    # to the host in our request. We will specify it
    # as Content parameter to the request method of
    # our choosing.
    my %args = (defined($instdata->{'request_data'}) &&
	        $instdata->{'request_data'} ne "") ?
			(Content => $instdata->{'request_data'}):();

    # Method HTTP GET ?
    if($self->{'request_method'} == &HTTP_GET) {
	return $instdata->{'ua'}->get($instdata->{'request_url'},
				      %args);
    # Method HTTP POST ?
    } elsif($self->{'request_method'} == &HTTP_POST) {
	return $instdata->{'ua'}->post($instdata->{'request_url'},
				       $instdata->{'form'},
				       %args);
    # Method HTTP PUT ?
    } elsif($self->{'request_method'} == &HTTP_PUT) {
	return $instdata->{'ua'}->put($instdata->{'request_url'},
				      $instdata->{'form'},
				      %args);
    # Method HTTP DELETE ?
    } elsif($self->{'request_method'} == &HTTP_DELETE) {
	return $instdata->{'ua'}->delete($instdata->{'request_url'},
					 %args);
    }

    return undef;
}
#
# Substitute variable names in a string with their values
#
#  Variables appearing in given string will be replaced by their
#  current values. Supported variables are:
#
#     $lb		- name of the load balancer that sent the update
#     $seq		- load balancer's current sequence number
#     $host		- IP address returned by input module's host() method
#     $ipv4		- device's IPv4 address, if any
#     $ipv6		- device's IPv6 address, if any
#     $input		- name of input module's instance monitoring this device
#     $preference	- number designating device's order of preference
#			  assigned by the load balancer
#
#   Input:	1. self object reference
#		2. string to be xlated
#		3. instance data hashref
#
#  Output:	1. xlated string
#
sub xlat($$$) {
    my ($self, $string, $instdata) = @_;

    my $replace = sub {
	return defined($instdata->{'params'}{$1}) ?
			$instdata->{'params'}{$1}:'';
    };

    # Do variable substitution
    $string =~ s/\$([a-zA-Z0-9\_]+)/&$replace/eg;

    return $string;
}

##############################################################################################

#
# XML document parser
#
#   Input:	1. self object reference
#		2. instance data hashref
#		3. raw document data
#
#   Output:	1. array of extracted values,
#		   empty list, if parsing failed
#
sub parser_xml($$$) {
    my ($self, $instdata, $document) = @_;
    my @values = ();

    # Parse XML document we got
    my $data = $instdata->{'xml'}->XMLin($document);
    if(defined($data)) {
	# Format nested hash keys from configuration
	foreach my $field (@{$self->{'fields'}}) {
	    my @valpath = split('/', $field);
	    if(@valpath) {
		my $hashkey = "{'".join("'}{'", @valpath)."'}";
		my $value;
		# Requested key must not be a hash or an array
		if(eval 'ref($data->'.$hashkey.') eq ""') {
		    # Retrieve the value from parsed XML data.
		    eval '$value = $data->'.$hashkey;
		    # Sort values in the same order fields
		    # are defined in the configuration
		    push @values, $value;
		}
	    }
	}
    }
    return @values;
}
#
# JSON document parser
#
#   Input:	1. self object reference
#		2. instance data hashref
#		3. raw document data
#
#   Output:	1. array of extracted values,
#		   empty list, if parsing failed
#
sub parser_json($$$) {
    my ($self, $instdata, $document) = @_;
    my @values = ();

    # Parse JSON document we got
    my $data = $instdata->{'json'}->allow_nonref->utf8->relaxed->escape_slash->loose->allow_singlequote->allow_barekey->decode($document);
    if(defined($data) && ref($data) eq 'HASH') {
	# Format nested hash keys from configuration
	foreach my $field (@{$self->{'fields'}}) {
	    my $hashkey;
	    # Tokenize fully qualified value namespace
	    my @valpath = split('::', $field);
	    # Each namespace element can either be
	    # a hashname/hashkey or an array element
	    foreach my $elem (@valpath) {
		# Array element is defined as 'key[index]'
		# Hashname/hashkey is defined simply as key
		my ($key, $index) = ($elem =~ /^\s*([^\[\]\s]+)(?:\[\s*(\d+)\s*\])?\s*$/);
		# Key name must be defined at all times
		# or the entire path is invalid
		unless(defined($key) && $key ne "") {
		    undef $hashkey;
		    last;
		}
		# Format deep hashkey
		$hashkey .= '->'.((defined($index) && $index ne "") ? '['.$2.']':'{\''.$1.'\'}');
	    }
	    my $value;
	    # Requested key must not be a hash or an array
	    if(eval 'ref($data'.$hashkey.') eq ""') {
		# Retrieve the value from parsed JSON data.
		eval '$value = $data'.$hashkey;
		# Sort values in the same order fields
		# are defined in the configuration
		push @values, $value;
	    }
	}
    }
    return @values;
}
#
# Generic (regexp) document parser
#
#   Input:	1. self object reference
#		2. instance data hashref
#		3. raw document data
#
#   Output:	1. array of extracted values,
#		   empty list, if parsing failed
#
sub parser_generic($$$) {
    my ($self, $instdata, $document) = @_;
    my @values = ();

    foreach my $regexp (@{$self->{'fields'}}) {
	@values = (@values, ($document =~ /$regexp/));
    }

    return @values;
}

1;
