#
# module::curl.pm
#
# Copyright (c) 2014 Marko Dinic <marko@yu.net>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.
#

package module::curl;

##############################################################################################

use strict;
use warnings;

##############################################################################################

use URI;
use JSON;
use LWP::Simple;
use XML::Simple;
use Config::ContextSensitive qw(:macros);

##############################################################################################

use api::module;

##############################################################################################

our @ISA = qw(api::module);

##############################################################################################

my $CONF_TEMPLATE = SECTION(
    DIRECTIVE('check_interval', ARG(CF_INTEGER, STORE(TO 'MODULE', KEY { '$SECTION' => { 'check_interval' => '$VALUE' } }), DEFAULT '0')),
    DIRECTIVE('request_timeout', ARG(CF_INTEGER, STORE(TO 'MODULE', KEY { '$SECTION' => { 'request_timeout' => '$VALUE' } }), DEFAULT '3')),
    DIRECTIVE('request_url', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$SECTION' => { 'request_url' => '$VALUE' } }))),
    DIRECTIVE('request_method', MAP(FROM 'HTTP_METHODS', STORE(TO 'MODULE', KEY { '$SECTION' => { 'request_method' => '$VALUE' } }), DEFAULT 'get')),
    DIRECTIVE('request_data', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$SECTION' => { 'request_data' => ['$VALUE'] } }))),
    DIRECTIVE('form_field', SKIP, ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$SECTION' => { 'form' => { '$ARG[1]' => '$VALUE' } } }))),
    DIRECTIVE('user_agent', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$SECTION' => { 'user_agent' => '$VALUE' } }), DEFAULT 'Mozilla/3.0')),
    DIRECTIVE('content_type', ARG(CF_STRING, POSTPARSER(&check_parser), STORE(TO 'MODULE', KEY { '$SECTION' => { 'content_type' => '$VALUE' } }))),
    DIRECTIVE('username', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$SECTION' => { 'username' => '$VALUE' } }))),
    DIRECTIVE('password', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$SECTION' => { 'password' => '$VALUE' } }))),
    DIRECTIVE('field', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$SECTION' => { 'fields' => ['$VALUE'] } })))
);

##############################################################################################

use constant {
    HTTP_GET	=> 1,
    HTTP_POST	=> 2,
    HTTP_PUT	=> 4,
    HTTP_DELETE	=> 8
};

our %HTTP_METHODS = (
    'get'	=> &HTTP_GET,
    'post'	=> &HTTP_POST,
    'put'	=> &HTTP_PUT,
    'delete'	=> &HTTP_DELETE
);

##############################################################################################

sub register() {
    return $CONF_TEMPLATE;
}

sub daemonize($) {
    my $self = shift;

    my $instdata = {};

    # Set initial timeout for initialize()
    $self->set_initialize_timeout($self->{'request_timeout'});

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
    $self->set_reinitialize_timeout($self->{'request_timeout'});

    # Create UserAgent object
    my $ua = LWP::UserAgent->new();
    return undef unless defined($ua);

    # Identify ourselves
    $ua->agent($self->{'user_agent'});
    # Set timeout value
    $ua->timeout($self->{'request_timeout'});
    # Flush connection cache
    my $cc = $ua->conn_cache;
    $cc->prune if defined($cc);
    # Store User-Agent object
    # in our internal data store
    $instdata->{'ua'} = $ua;

    # Cleanup runtime data and events
    $self->cleanup($instdata);

    # This module can be used either as input or
    # output module for a load balancer, but never
    # both at the same time. If curl is required
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

    # Prepare content parsers
    $instdata->{'xml'} = XML::Simple->new();
    return undef unless defined($instdata->{'xml'});
    $instdata->{'json'} = JSON->new();
    return undef unless defined($instdata->{'json'});

    # Prepare new base URL
    my $uri = URI->new($self->{'request_url'});
    return undef unless defined($uri);

    # If form is defined ..
    if(defined($self->{'form'}) && scalar(keys %{$self->{'form'}}) > 0) {
	# ... and the request method is GET or DELETE ...
	if($self->{'request_method'} & (HTTP_GET|HTTP_DELETE)) {
	    # ... append it (escaped) to the base URL
	    $uri->query_form($self->{'form'});
	# Otherwise, form data will be used as is
	} else {
	    $instdata->{'form'} = $self->{'form'};
	}
    }

    # Store full escaped URL
    $instdata->{'request_url'} = $uri->as_string;

    # If request data is defined ...
    if(defined($self->{'request_data'}) &&
       scalar(@{$self->{'request_data'}}) > 0) {
        # ... store it as a single string
	$instdata->{'request_data'} = join("\n", @{$self->{'request_data'}});
    }

    # Create/modify data collector
    $instdata->{'collector'} = defined($instdata->{'collector'}) ?
					$self->api->modify_timer_event($instdata->{'collector'},
								       'args' => [ $self, $instdata ],
								       'interval' => $self->{'check_interval'},
								       'timeout' => $self->{'request_timeout'} + 1):
					$self->api->create_timer_event('interval' => $self->{'check_interval'},
								       'handler' => \&collect,
								       'args' => [ $self, $instdata ],
								       'timeout' => $self->{'request_timeout'} + 1,
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
    delete $instdata->{'request_data'};
    delete $instdata->{'request_url'};
    delete $instdata->{'collector'};
    delete $instdata->{'params'};
    delete $instdata->{'form'};
    delete $instdata->{'json'};
    delete $instdata->{'xml'};
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

    # Prepare new base URL by xlating variables, if any
    my $uri = URI->new($self->xlat($self->{'request_url'}, $instdata));
    # If URI object creation failed ...
    unless(defined($uri)) {
	# Make a note in the log
	$self->api->logging('LOG_ERR', "cURL backend %s: failed to initialize base URL",
				       $self->{'instance'});
	return;
    }

    # If form is defined ..
    if(defined($self->{'form'}) &&
       scalar(keys %{$self->{'form'}}) > 0) {
	# Substitute variable names with values in
	# both form field names and field values
	foreach my $name (keys %{$self->{'form'}}) {
	    # xlat form field name
	    my $xname = $self->xlat($name, $instdata);
	    if(defined($xname) && $xname ne '') {
		# xlat form field value
		my $xvalue = $self->xlat($self->{'form'}{$name}, $instdata);
		# Store xlated form field
		$instdata->{'form'}{$xname} = defined($xvalue) ? $xvalue:'';
	    }
	}
	# If request method is GET or DELETE ...
	if($self->{'request_method'} & (HTTP_GET|HTTP_DELETE)) {
	    # ... append it (escaped) to the base URL
	    $uri->query_form($instdata->{'form'});
	}
    }

    # Store full escaped URL
    $instdata->{'request_url'} = $uri->as_string;

    # If request data is defined ...
    if(defined($self->{'request_data'}) &&
       scalar(@{$self->{'request_data'}}) > 0) {
        # ... store it xlated as a single string
	$instdata->{'request_data'} = $self->xlat(join("\n", @{$self->{'request_data'}}), $instdata);
    }

    # Update the target with data
    # received from load balancer
    my $res = $self->curl($instdata);
    # Check if request failed
    unless($res->is_success()) {
	# Make a note in the log
	$self->api->logging('LOG_ERR', "cURL backend %s failed to update resource %s: %s",
				       $self->{'instance'},
				       $self->{'request_url'},
				       $res->status_line());
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

    # Request the document
    my $res = $instance->curl($instdata);
    # Any response whatsoever ?
    unless(defined($res)) {
	# Notify the load balancer the host is down
	$instance->api->logging('LOG_INFO', "cURL collector %s down",
					    $instance->{'instance'});
	return $instance->down;
    }

    # If we received the document,
    # we can proceed with parsing.
    if($res->is_success()) {

	# Find coderef to the parser for this content type
	my $parser = $instance->can('parser_'.$instance->{'content_type'});
	unless(defined($parser) && ref($parser) eq 'CODE') {
	    $instance->api->logging('LOG_ERR', "cURL collector %s: %s content type parser is missing",
					    $instance->{'instance'},
					    $instance->{'content_type'});
	    return $instance->down;
	}

	# Invoke content parser
	my @values = $parser->($instance, $instdata, $res->content());

	if(scalar(@values) > 0) {

	    # Send serialized collected data to the load balancer
	    $instance->api->logging('LOG_INFO', "cURL collector %s: host %s up: ".join('=%s, ', @{$instance->{'fields'}})."=%s",
						$instance->{'instance'},
						join(', ', @addr),
						@values);

	    return $instance->up(@values);

	} else {

	    # Notify the load balancer the host is down
	    $instance->api->logging('LOG_INFO', "cURL collector %s: host %s down: failed to collect data",
					        $instance->{'instance'},
					        join(', ', @addr));

	    return $instance->down;
	}

    } else {

	# Notify the load balancer the host is down
	$instance->api->logging('LOG_INFO', "cURL collector %s: host %s down: failed to get() page: %s",
					    $instance->{'instance'},
					    join(', ', @addr),
					    $res->status_line());

	return $instance->down;

    }

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

##############################################################################################

# This is a postparser callback for our conf template
sub check_parser($$$$$$$) {
    my ($conf, $directive_name, $value, $dest, $map, $section, $nested_section) = @_;

    my $parser = module::curl->can('parser_'.$value);

    return (defined($parser) && ref($parser) eq 'CODE') ?
		1:(0, "content type ".$value." is not supported");
}

1;
