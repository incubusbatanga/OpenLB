#
# module::nameserver.pm
#
# Copyright (c) 2014 Marko Dinic <marko@yu.net>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.
#

package module::nameserver;

##############################################################################################

use strict;
use warnings;

##############################################################################################

use Socket;
use Socket6;
use Net::Domain qw(hostfqdn);
use Net::DNS::Nameserver;
use Net::Telnet;
use Net::Patricia;
use POSIX qw(:signal_h :sys_wait_h);
use Config::ContextSensitive qw(:macros);

##############################################################################################

use api::module;
use api::util::event;

##############################################################################################

our @ISA = qw(api::module);

##############################################################################################

our $CONF_TEMPLATE = SECTION(
    DIRECTIVE('listen_on', ARG(CF_ARRAY|CF_STRING, STORE(TO 'MODULE', KEY { '$SECTION' => { 'listen_on' => ['$VALUES'] } }))),
    DIRECTIVE('port', ARG(CF_PORT, STORE(TO 'MODULE', KEY { '$SECTION' => { 'port' => '$VALUE' } }), DEFAULT '53')),
    DIRECTIVE('nameservers', ARG(CF_ARRAY|CF_STRING, STORE(TO 'MODULE', KEY { '$SECTION' => { 'ns' => ['$VALUES'] } }))),
    DIRECTIVE('ttl', ARG(CF_INTEGER, STORE(TO 'MODULE', KEY { '$SECTION' => { 'ttl' => '$VALUE' } } ), DEFAULT '5')),
    DIRECTIVE('query', SKIP, REQUIRE(DIRECTIVE('answer', REQUIRE(
	    DIRECTIVE('from', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$SECTION' => { 'query' => { '$ARG[1]' => { 'answer' => '$VALUE' } } } }))),
	    DIRECTIVE('to', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$SECTION' => { 'query' => { '$ARG[1]' => { 'origin' => '$VALUE' } } } })), ALLOW(
		DIRECTIVE('default', REQUIRE(DIRECTIVE('from', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$SECTION' => { 'query' => { '$ARG[1]' => { 'answer' => '$VALUE' } } } })))))
	    ))
	))), OPTIONAL(DIRECTIVE('ttl', ARG(CF_INTEGER, STORE(TO 'MODULE', KEY { '$SECTION' => { 'query' => { '$ARG[1]' => { 'ttl' => '$VALUE' } } } }))))
    ),
    DIRECTIVE('origin', SECTION_NAME, SECTION(
	DIRECTIVE('neighbor', REQUIRE(
	    DIRECTIVE('local', OPER(STORE(TO 'MODULE', KEY { '$PARENT_SECTION' => { 'origin' => { '$SECTION' => { 'neighbor' => 'local' } } } }))),
	    DIRECTIVE('host', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$PARENT_SECTION' => { 'origin' => { '$SECTION' => { 'neighbor' => '$VALUE' } } } })), OPTIONAL(
		DIRECTIVE('port', ARG(CF_PORT, STORE(TO 'MODULE', KEY { '$PARENT_SECTION' => { 'origin' => { '$SECTION' => { 'port' => '$VALUE' } } } }), DEFAULT '2605')),
		DIRECTIVE('username', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$PARENT_SECTION' => { 'origin' => { '$SECTION' => { 'username' => '$VALUE' } } } }))),
		DIRECTIVE('password', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$PARENT_SECTION' => { 'origin' => { '$SECTION' => { 'password' => '$VALUE' } } } }))),
		DIRECTIVE('timeout', ARG(CF_INTEGER, STORE(TO 'MODULE', KEY { '$PARENT_SECTION' => { 'origin' => { '$SECTION' => { 'remote_timeout' => '$VALUE' } } } }), DEFAULT '2')),
		DIRECTIVE('retries', ARG(CF_INTEGER, STORE(TO 'MODULE', KEY { '$PARENT_SECTION' => { 'origin' => { '$SECTION' => { 'remote_retries' => '$VALUE' } } } }), DEFAULT '3'))
	    ))
	)),
	DIRECTIVE('update', REQUIRE(
	    DIRECTIVE('interval', ARG(CF_INTEGER, STORE(TO 'MODULE', KEY { '$PARENT_SECTION' => { 'origin' => { '$SECTION' => { 'update_interval' => '$VALUE' } } } }), DEFAULT '300')),
	    DIRECTIVE('timeout', ARG(CF_INTEGER, STORE(TO 'MODULE', KEY { '$PARENT_SECTION' => { 'origin' => { '$SECTION' => { 'update_timeout' => '$VALUE' } } } }), DEFAULT '60'))
	)),
	DIRECTIVE('queries', REQUIRE(
	    DIRECTIVE('via', REQUIRE(
		DIRECTIVE('inet', SKIP, REQUIRE(
		    DIRECTIVE('answer', REQUIRE(
			DIRECTIVE('/^from|with$/', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$PARENT_SECTION' => { 'origin' => { '$SECTION' => { 'nexthop' => { 'ipv4' => { '$ARG[3]' => '$VALUE' } } } } } })))
		    ))
		)),
		DIRECTIVE('inet6', SKIP, REQUIRE(
		    DIRECTIVE('answer', REQUIRE(
			DIRECTIVE('/^from|with$/', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$PARENT_SECTION' => { 'origin' => { '$SECTION' => { 'nexthop' => { 'ipv6' => { '$ARG[3]' => '$VALUE' } } } } } })))
		    ))
		))
	    )),
	    DIRECTIVE('from', REQUIRE(
		DIRECTIVE('inet', SKIP, REQUIRE(
		    DIRECTIVE('answer', REQUIRE(
			DIRECTIVE('/^from|with$/', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$PARENT_SECTION' => { 'origin' => { '$SECTION' => { 'prefix' => { 'ipv4' => { '$ARG[3]' => '$VALUE' } } } } } })))
		    ))
		)),
		DIRECTIVE('inet6', SKIP, REQUIRE(
		    DIRECTIVE('answer', REQUIRE(
			DIRECTIVE('/^from|with$/', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$PARENT_SECTION' => { 'origin' => { '$SECTION' => { 'prefix' => { 'ipv6' => { '$ARG[3]' => '$VALUE' } } } } } })))
		    ))
		))
	    ))
	))
    ))
);

##############################################################################################

sub register() {
    return $CONF_TEMPLATE;
}

sub initialize($$) {
    my ($self, $instdata) = @_;

    # Apply reconfigurable parts of configuration
    $self->reinitialize($instdata)
	or return undef;


    # Create new nameserver listener. Unfortunately,
    # this can only be done here, on module init,
    # because Net::DNS::Nameserver doesn't allow us
    # to close/reopen listener sockets. Thus, if
    # listener addresses or port changes, module has
    # to do a hard restart.
    $instdata->{'ns'} = Net::DNS::Nameserver->new(LocalAddr => $instdata->{'listen_on'},
						  LocalPort => $instdata->{'port'},
						  ReplyHandler => sub {
							return $self->nameserver_responder($instdata, @_);
						  },
						  Verbose => 0,
						  Truncate => 1);

    unless(defined($instdata->{'ns'})) {
	$self->api->logging('LOG_ERR', "Nameserver backend %s init: failed to create nameserver instance",
				       $self->{'instance'});
	return undef;
    }

    # Create loop event that processes DNS queries
    # by invoking nameserver's main loop single
    # iteration at a time.
    $instdata->{'daemon'} = $self->api->create_recurring_event('handler' => \&daemon_loop,
							       'args' => [ $self, $instdata ]);

    unless(defined($instdata->{'daemon'})) {
	$self->api->logging('LOG_ERR', "Nameserver backend %s init: failed to init nameserver daemon loop",
				       $self->{'instance'});
	return undef;
    }

    # Register origin child processes' reaper
    $self->api->create_reaping_event('handler' => sub {
					my ($event, $pid) = @_;
					# Identify origin this child process was bound to
					my $origin = $instdata->{'child'}{$pid}{'origin'};
					my $channel = $instdata->{'child'}{$pid}{'channel'};
					if(defined($channel)) {
					    # Remove prefix collector for this origin daemon
					    $self->api->destroy_io_event($channel, 'r');
					    # Close our pipe to the origin
					    close($channel);
					}
					# Remove dead child process from the map
					delete $instdata->{'child'}{$pid};
					# If we are still running ...
					if($self->running() &&
					   defined($self->{'origin'}) &&
					   defined($self->{'origin'}{$origin})) {
					    # Make a note in the log
					    $self->api->logging('LOG_WARNING', "Nameserver backend %s: restarting query origin %s",
									       $self->{'instance'},
									       $origin);
					    # Schedule origin daemon re-launch
					    $self->api->create_recurring_event('handler' => sub { $self->init_origin($instdata, $origin); },
									       'delay' => 1,
									       'limit' => 1);
					}
				     });

    # Initialize all query origins on startup.
    # During reinitialize, reaper will restart
    # origin daemons if required by the new
    # configuration
    foreach my $origin (keys %{$self->{'origin'}}) {
	# Query origin is a child process that collects BGP prefixes
	# and feeds them to the nameserver module in order to update
	# query origin lookup tables
	my $pid = $self->init_origin($instdata, $origin);
	unless($pid) {
	    $self->api->logging('LOG_ERR', "Nameserver backend %s init: failed to init query origin %s",
					    $self->{'instance'},
					    $origin);
	    return undef;
	}
    }

    return $instdata;
}

sub reinitialize($$) {
    my ($self, $instdata) = @_;

    # Get our own fqdn
    $instdata->{'hostname'} = hostfqdn();
    return undef unless defined($instdata->{'hostname'});

    # Nameservers are either explicitly defined
    # or it is us (our fqdn and IPv4/IPv6 addresses)
    my $nameservers = defined($self->{'ns'}) ?
			$self->{'ns'}:[ $instdata->{'hostname'} ];

    # Resolve nameservers' FQDNs
    foreach my $ns (@{$nameservers}) {
	# Resolve name server's IPv4 addresses
	my @ai4 = getaddrinfo($ns, 0, AF_INET);
	for(my $i = 0; $i < scalar(@ai4); $i += 5) {
	    if(defined($ai4[$i+3])) {
		my ($host) = getnameinfo($ai4[$i+3], NI_NUMERICHOST);
		$instdata->{'nameservers'}{$ns}{'ipv4'}{$host} = 1;
	    }
	}
	# Resolve name server's IPv6 addresses
	my @ai6 = getaddrinfo($ns, 0, AF_INET6);
	for(my $i = 0; $i < scalar(@ai6); $i += 5) {
	    if(defined($ai6[$i+3])) {
		my ($host) = getnameinfo($ai6[$i+3], NI_NUMERICHOST);
		$instdata->{'nameservers'}{$ns}{'ipv6'}{$host} = 1;
	    }
	}
    }

    # Our local addresses
    my $local_addr = [ ($self->api->get_local_addr('lo')), ($self->api->get_local_addr()) ];
    # Array of addresses to listen on
    my $listen_on = (defined($self->{'listen_on'}) &&
		     ref($self->{'listen_on'}) eq "ARRAY") ?
			    $self->{'listen_on'}:$local_addr;
    # Port to listen on
    my $port = (defined($self->{'port'}) && $self->{'port'} ne "") ?
			$self->{'port'}:"53";

    # Temporary lookup hash
    my %addr_diff = ();
    # Put listener addresses into hash for easy lookup
    foreach my $addr (@{$listen_on}) {
	$addr_diff{$addr} = 1;
    }
    # If we got previously saved listener addresses,
    # we are getting reconfigured. Unfortunately, we
    # cannot simply close previous listeners, because
    # Net::DNS::Nameserver doesn't support that.
    # Instead we need to determine if listener config
    # has changed and do a hard restart if it did.
    if(defined($instdata->{'listen_on'}) &&
       ref($instdata->{'listen_on'}) eq "ARRAY") {
	# Eliminate addresses we are already bound to
	foreach my $addr (@{$instdata->{'listen_on'}}) {
	    delete $addr_diff{$addr};
	}
	# If listener configuration hasn't changed,
	# lookup hash should be empty and port should
	# be equal to the saved one. If not, we need
	# to make main process restart us.
	if(keys %addr_diff > 0 || $port != $instdata->{'port'}) {
	    # Gracefully shutdown. Since global shutdown
	    # has not been initiated, main process will
	    # restart us.
	    $self->abort();
	    # This is just to prevent reinitialize to fail
	    return $instdata;
	}
    }

    # Save listener address and port
    $instdata->{'listen_on'} = $listen_on;
    $instdata->{'port'} = $port;

    # First, stop prefix collection, if it was up
    $self->cleanup($instdata);

    # Set the flag that signals the rest of the code
    # whether split view is configured or not
    $instdata->{'isplitview'} = keys %{$self->{'origin'}};

    return $instdata;
}

sub process($$$$$$$$) {
    my ($self, $instdata, $lb, $seq, $preference, $input, $ipv4, $ipv6) = @_;

    # Remember the most prefered host (the first one received)
    # when new sequence of load balancing data begins
    if(!defined($instdata->{'lb'}{$lb}{'seq'}) ||
       $seq > $instdata->{'lb'}{$lb}{'seq'}) {
       $instdata->{'lb'}{$lb}{'seq'} = $seq;
	if(defined($preference) && $preference > 0) {
	    $instdata->{'lb'}{$lb}{'rdata'}{'ipv6'} = $ipv6;
	    $instdata->{'lb'}{$lb}{'rdata'}{'ipv4'} = $ipv4;
	} else {
	    $instdata->{'lb'}{$lb}{'rdata'}{'ipv6'} = undef;
	    $instdata->{'lb'}{$lb}{'rdata'}{'ipv4'} = undef;
	}
    }
    # Explicitly return nothing
    return;
}

sub abort($$) {
    my ($self, $instdata) = @_;

    # Begin complete module shutdown
    $self->shutdown();
    # Terminate origin daemons
    $self->cleanup($instdata);
    # Register recurring event that will wait
    # for origin daemons to exit and then
    # transition to stopped state.
    $self->api->create_recurring_event('handler' => sub {
					    # Once all origin daemons are gone ...
					    unless(keys %{$instdata->{'child'}} > 0) {
						# ... finally stop processing and exit
						$self->stop();
					    }
				       });
}

sub cleanup($$) {
    my ($self, $instdata) = @_;

    # Terminate all origin daemons
    foreach my $pid (keys %{$instdata->{'child'}}) {
	# Signal origin child process to end
	kill 'TERM', $pid;
    }
}

##############################################################################################

sub daemon_loop($$$) {
    my ($event, $instance, $instdata) = @_;

    # Skip if nameserver object is not defined
    # or we are no longer in running state
    return unless defined($instdata->{'ns'}) &&
		  $instance->running();

    # Wait 10ms for DNS requests
    # and process them, if any
    $instdata->{'ns'}->loop_once(0.01);

    # Explicitly return nothing
    return;
}

##############################################################################################

#
# Net:DNS::Nameserver reply handler
#
#  Input:	1. backend instance object reference
#		2. backend instande data
#		3. DNS query name (fqdn of the host whose IP address client seeks)
#		4. DNS query class 
#		5. DNS query type (the type of dns record the client wants)
#		6. (optional) dns client's IP address
#		7. (optional) reference to request packet
#		8. (optional) nameserver instance handle
#
#  Output:	1. nameserver return code
#		2. reference to answer section array
#               3. reference to authority section array
#		4. reference to additional section array
#		5. (optional) reference to header hash
#
sub nameserver_responder() {
    my ($self, $instdata, $qname, $qclass, $qtype, $client_ip, $query_packet, $sock) = @_;
    my ($domain, $ttl);
    my $rcode = 0;
    my @ans = ();
    my @auth = ();
    my @add = ();

    # Make everything case-insensitive
    # by lowercasing everything.
    $qname = lc($qname);
    # Query is a configured fqdn ?
    if(defined($self->{'query'}{$qname})) {
	# Extract domain part from fqdn
	($domain) = ($qname =~ /^[^\.]+\.(.*)$/);
	# Record TTL should be as small as possible
	# since it is supposed to change frequently
	$ttl = defined($self->{'query'}{$qname}{'ttl'}) ? 
			$self->{'query'}{$qname}{'ttl'}:$self->{'ttl'};
    # Query is a domain part of a configured fqdn ?
    } elsif(scalar(grep(/^[^\.]+\.$qname$/, (keys %{$self->{'query'}})))) {
	# Keep it as the domain
	$domain = $qname;
	# Default 'zone' TTL
	$ttl = $self->{'ttl'};
    }

    if(defined($domain)) {

	# Format and store SOA record into given section
	my $SOA = sub {
	    my $ns = defined($self->{'ns'}) ?
			$self->{'ns'}[0]:$instdata->{'hostname'};
	    # Use unix timestamp as serial and
	    # refresh = retry = expire = min = ttl
	    # and first configured nameserver as
	    # authoritative nameserver
	    push @{$_[0]}, Net::DNS::RR->new($domain.". ".$ttl." IN SOA ".$ns.". hostmaster.".$domain.". ".time()." ".$ttl." ".$ttl." ".$ttl." ".$ttl);
	    $rcode++;
	};

	# Format and store NS records into given sections
	my $NS = sub {
	    # Process all configured nameservers
	    foreach my $ns (keys %{$instdata->{'nameservers'}}) {
		# Store NS record into one section
		push @{$_[0]}, Net::DNS::RR->new($domain.". ".$ttl." IN NS ".$ns.".");
		# Store A records for listed NS records into additional section
		foreach my $addr (keys %{$instdata->{'nameservers'}{$ns}{'ipv4'}}) {
		    # Store A record of the nameserver
		    # into additional section
		    push @add, Net::DNS::RR->new($ns.". ".$ttl." IN A ".$addr);
		    $rcode++;
		}
		# Store AAAA records for listed NS records into additional section
		foreach my $addr (keys %{$instdata->{'nameservers'}{$ns}{'ipv6'}}) {
		    # Store AAAA record of the nameserver
		    # into additional section
		    push @add, Net::DNS::RR->new($ns.". ".$ttl." IN AAAA ".$addr);
		    $rcode++;
		}
	    }
	};

	# Format and store A record for given fqdn into answer section
	my $A = sub {
	    my $q = shift;
	    my ($lb, $rdata);
	    # Is split view configured ?
	    if($instdata->{'isplitview'}) {
		# Is query configured to use split-view ?
		my $origin = $self->{'query'}{$q}{'origin'};
		# Query origin must exist
		if(defined($origin) && defined($instdata->{'origin'}{$origin})) {
		    # Match client's IP address against lookup trie
		    my $nh = $self->api->is_ipv4($client_ip) ?
				    (defined($instdata->{'origin'}{$origin}{'lookup'}{'ipv4'}) ?
					$instdata->{'origin'}{$origin}{'lookup'}{'ipv4'}->match_string($client_ip):undef):
				    (defined($instdata->{'origin'}{$origin}{'lookup'}{'ipv6'}) ?
					$instdata->{'origin'}{$origin}{'lookup'}{'ipv6'}->match_string($client_ip):undef);
		    # If client IP matches ...
		    if(defined($nh)) {
			# If returned next hop is an IPv4 address ...
			if($self->api->is_ipv4($nh)) {
			    # ... it's our response
			    # IP address directly
			    $rdata = $nh;
			# If returned next hop is an IPv6 address ...
			} elsif($self->api->is_ipv6($nh)) {
			    # ... return NXDOMAIN
			    return 0;
			} else {
			    # ... otherwise, it's the name
			    # of load balancer that provides
			    # response IP address
			    $lb = $nh;
			}
		    }
		}
	    }
	    # If geo IP lookup (if enabled) didn't provide
	    # load balancer yet ...
	    unless(defined($lb)) {
		# ... get load balancer that provides
		# (default) answers for given query
		$lb = $self->{'query'}{$q}{'answer'};
	    }
	    # If geo IP lookup (if enabled) didn't provide
	    # answer yet ...
	    unless(defined($rdata)) {
		# Response to A query will be the IPv4 address of
		# the target host of the input with the higest
		# preference value
		if(defined($lb)) {
		    $rdata = $instdata->{'lb'}{$lb}{'rdata'}{'ipv4'};
		}
	    }
	    # NXDOMAIN if we have no answer
	    return 0 unless defined($rdata);
	    # Otherwise, store A record into answer section
	    push @ans, Net::DNS::RR->new($q.". ".$ttl." IN A ".$rdata);
	    return 1;
	};

	# Format and store AAAA record for given fqdn into answer section
	my $AAAA = sub {
	    my $q = shift;
	    my ($lb, $rdata);
	    # Is split view configured ?
	    if($instdata->{'isplitview'}) {
		# Is query configured to use split-view ?
		my $origin = $self->{'query'}{$q}{'origin'};
		# Query origin must exist
		if(defined($origin) && defined($instdata->{'origin'}{$origin})) {
		    # Match client's IP address against lookup trie
		    my $nh = $self->api->is_ipv6($client_ip) ?
				    (defined($instdata->{'origin'}{$origin}{'lookup'}{'ipv6'}) ?
					$instdata->{'origin'}{$origin}{'lookup'}{'ipv6'}->match_string($client_ip):undef):
				    (defined($instdata->{'origin'}{$origin}{'lookup'}{'ipv4'}) ?
					$instdata->{'origin'}{$origin}{'lookup'}{'ipv4'}->match_string($client_ip):undef);
		    # If client IP matches ...
		    if(defined($nh)) {
			# If returned next hop is an IPv6 address ...
			if($self->api->is_ipv6($nh)) {
			    # ... it's our response
			    # IP address directly
			    $rdata = $nh;
			# If returned next hop is an IPv4 address ...
			} elsif($self->api->is_ipv4($nh)) {
			    # ... return NXDOMAIN
			    return 0;
			} else {
			    # ... otherwise, it's the name
			    # of load balancer that provides
			    # response IP address
			    $lb = $nh;
			}
		    }
		}
	    }
	    # If geo IP lookup (if enabled) didn't provide
	    # load balancer yet ...
	    unless(defined($lb)) {
		# ... get load balancer that provides
		# (default) answers for given query
		$lb = $self->{'query'}{$q}{'answer'};
	    }
	    # If geo IP lookup (if enabled) didn't provide
	    # answer yet ...
	    unless(defined($rdata)) {
		# Response to AAAA query will be the IPv6 address of
		# the target host of the input with the higest
		# preference value
		if(defined($lb)) {
		    $rdata = $instdata->{'lb'}{$lb}{'rdata'}{'ipv6'};
		}
	    }
	    # NXDOMAIN if we have no answer
	    return 0 unless defined($rdata);
	    # Store AAAA record into answer section
	    push @ans, Net::DNS::RR->new($q.". ".$ttl." IN AAAA ".$rdata);
	    return 1;
	};

	# Process the following query types ...

	if($qtype eq "A") {

	    if($A->($qname)) {
		$NS->(\@auth);
	    }

	} elsif($qtype eq "AAAA") {

	    if($AAAA->($qname)) {
		$NS->(\@auth);
	    }

	} elsif(($qtype eq "SOA" || $qtype eq "NS") &&
		defined($self->{'query'}{$qname})) {

	    $SOA->(\@auth);

	} elsif($qtype eq "SOA") {

	    $SOA->(\@ans);
	    $NS->(\@auth);

	} elsif($qtype eq "NS") {

	    $NS->(\@ans);

	} elsif($qtype eq "AXFR") {

	    # Pick up all configured fqdns whose
	    # domain parts match the query
	    my @records = grep(/^[^\.]+\.$qname$/, (keys %{$self->{'query'}}));
	    if(scalar(@records)) {
		# Begin zone transfer with SOA record
		$SOA->(\@ans);
		# Send nameservers
		$NS->(\@ans);
		# Send all configured records
		while(my $rec = shift @records) {
		    $A->($rec);
		    $AAAA->($rec);
		}
		# End zone transfer with SOA record
		$SOA->(\@ans);
	    }

	}

    }

    return ($rcode ? "NOERROR":"NXDOMAIN", \@ans, \@auth, \@add, { aa => 1 });
}

##############################################################################################

sub init_origin($$$) {
    my ($self, $instdata, $origin) = @_;
    my $fh;

    # Create query origin child process
    my $pid = open($fh, '-|');
    return 0 unless(defined($pid) && $pid > -1);

    # Parent side of the fork
    if($pid) {
	# Input channel from the child process
	# must be non blocking to keep things
	# smooth
	$self->api->set_nonblocking($fh);
	# Keep file handle to the origin child process
	$instdata->{'child'}{$pid}{'channel'} = $fh;
	# Keep child process => origin mapping
	$instdata->{'child'}{$pid}{'origin'} = $origin;
	# Grab prefixes from origin and update lookup tables
	$self->api->create_io_event('file' => $fh,
				    'op' => 'r',
				    'handler' => \&update_lookup_tables,
				    'args' => [ $self, $instdata, $origin ],
				    'timeout' => (defined($self->{'origin'}{$origin}{'update_timeout'}) &&
						  $self->{'origin'}{$origin}{'update_timeout'} > 0) ?
						    $self->{'origin'}{$origin}{'update_timeout'}:60,
				    'on_timeout' => sub {
					my $self = shift;
					$self->api->logging('LOG_ERR', "Nameserver backend %s: failed to collect prefixes in time from origin %s",
								       $self->{'instance'},
								       $origin);
				    });
	return $pid;
    }

    ## ORIGIN DAEMON CHILD PROCESS STARTS HERE

    $0 .= " [origin ".$origin." update daemon]";

    # Close backend's side of the pipe
    close($fh);
    # Setup our side of the pipe
    STDOUT->autoflush(1);

    # Save our origin identifier
    $instdata->{'origin'} = $origin;

    # Setup signal handlers
    $SIG{TERM} = $SIG{INT} = $SIG{HUP} = $SIG{CHLD} = $SIG{ALRM} = $SIG{PIPE} = 'IGNORE';

    $self->api->logging('LOG_INFO', "Nameserver backend %s: query origin %s started",
				    $self->{'instance'},
				    $origin);

    # Create event monitor to run prefix collection
    # periodically in a controlled environment
    $instdata->{'evmon'} = api::util::event->new();

    # Setup SIGTERM/SIGINT handler
    $instdata->{'evmon'}->create_termination_event('handler' => sub { $instdata->{'evmon'}->stop(); });

    my $interval = $self->{'origin'}{$origin}{'update_interval'};
    my $timeout = $self->{'origin'}{$origin}{'update_timeout'};

    # Register prefix collection code as a timer event
    $instdata->{'evmon'}->create_timer_event('interval' => (defined($interval) && $interval > 0) ? $interval:300,
					     'handler' => \&prefix_collector,
					     'args' => [ $self, $instdata, $origin ],
					     'timeout' => (defined($timeout) && $timeout > 0) ? $timeout:60,
 					     'on_timeout' => sub {
						    # Report error
						    $self->api->logging('LOG_ERR', "Nameserver backend %s: origin %s failed to complete update cycle in time",
										   $self->{'instance'},
										   $origin);
					     });

    # Main update loop
    while(!$instdata->{'evmon'}->stopped()) {
	# Poll for events
	my @handlers = $instdata->{'evmon'}->poll();
	while((my $handler = shift @handlers)) {
	    # Run actual update code
	    $handler->();
	}
    }

    $self->api->logging('LOG_INFO', "Nameserver backend %s: query origin %s ended",
				    $self->{'instance'},
				    $origin);

    # Restore signal handlers
    $SIG{TERM} = $SIG{INT} = $SIG{HUP} = $SIG{CHLD} = $SIG{ALRM} = $SIG{PIPE} = 'DEFAULT';

    exit(0);
}

sub update_lookup_tables($$$$$) {
    my ($fh, $instance, $instdata, $origin) = @_;

    # Collect a couple of lines from the feed
    # sent by origin's BGP prefix collector
    my @lines = <$fh>;
    # Process line by line
    foreach my $line (@lines) {
	# Do not loop if we are not
	# supposed to run anymore
	last unless($instance->running() &&
		    defined($line) &&
		    $line ne "");
	# We want to impose as little delay
	# on DNS responses as possible, so
	# we will invoke nameserver callback
	# here as well.
	$instdata->{'ns'}->loop_once(0);
	# If received line is not empty,
	# assume it is an update.
	chop $line;
	# Each update line is OP,AF,NETWORK/CIDR,NEXT_HOP
	my ($op, $af, $prefix, $answer) = split(/,/, $line);
	next unless defined($op) && defined($af);
	# On 'begin' we start with a fresh lookup table
	if($op eq 'begin') {
	    # Clear BGP prefix buffer
	    if($af eq 'ipv4') {
		# Create new IPv4 lookup trie
		$instdata->{'origin'}{$origin}{'tries'}{'ipv4'} = Net::Patricia->new(AF_INET);
	    } elsif($af eq 'ipv6') {
		# Create new IPv6 lookup trie
		$instdata->{'origin'}{$origin}{'tries'}{'ipv6'} = Net::Patricia->new(AF_INET6);
	    }
	} elsif($op eq 'end') {
	    # Once new lookup trie is complete ...
	    if($af =~ /^ipv[46]$/) {
		# ... make new lookup trie the active one
		$instdata->{'origin'}{$origin}{'lookup'}{$af} = $instdata->{'origin'}{$origin}{'tries'}{$af};
		# ... remove references
		delete $instdata->{'origin'}{$origin}{'tries'}{$af};
	    }
	} elsif($op eq 'add') {
	    # If received line is a proper update ...
	    if($af =~ /^ipv[46]$/ &&
	       defined($prefix) && $prefix ne "" &&
	       defined($answer) && $answer ne "" &&
	       defined($instdata->{'origin'}{$origin}{'tries'}{$af})) {
#print STDOUT "op=$op af=$af prefix=$prefix answer=$answer\n";
		# ... put prefix into destination trie
		$instdata->{'origin'}{$origin}{'tries'}{$af}->add_string($prefix, $answer);
	    }
	}
    }
}

sub prefix_collector($$$$) {
    my ($timer, $instance, $instdata, $origin) = @_;

    # This is our channel to the nameserver daemon
    my $channel = *STDOUT;

    # Mark the beginning of new update cycle
    print $channel "begin,ipv4\n";

    # Get IPv4 BGP table from Zebra/Quagga
    my @bgp_ipv4 = $instance->origin_collect_prefixes($instdata, $origin, 'ipv4');
    # Extract IPv4 prefix and next-hop information
    for(my $line = shift @bgp_ipv4; defined($line); $line = shift @bgp_ipv4) {
	# Abort if we were told to
	last unless $instdata->{'evmon'}->running();
	# IPv4 prefix can span from 1 to 2 lines
	# of raw 'show ip bgp' command output,
	# so we perform regexp match across every
	# 2 consecutive lines.
	my $route = $line.(defined($bgp_ipv4[0]) ? $bgp_ipv4[0]:'');
	# IPv4 prefix components
	my ($network, $class, $cidr, $next_hop) = ($route =~ /^\*?>?[a-z]?((\d+)\.\d+\.\d+\.\d+)(?:\/(\d+))?\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\d+\s+\d+/);
	next unless(defined($network) && $network ne '' &&
		    defined($next_hop) && $next_hop ne '' &&
		    defined($class) && $class ne '');
	# Fix Cisco's classful nonsense
	unless(defined($cidr) && $cidr ne "") {
	    # Class A
	    if($class < 127) {
		# /8
		$cidr = 8;
	    # Class B
	    } elsif($class > 127 && $class < 192) {
		# /16
		$cidr = 16;
	    # Class C
	    } elsif($class > 192 && $class < 224) {
		# /24
		$cidr = 24;
	    # Classes D and E ...
	    } else {
		# ... shouldn't appear in BGP feed
		next;
	    }
	}
	# Prefix in CIDR format
	my $prefix = $network.'/'.$cidr;
	# Map next hop to load balancer name
	# or direct A record data
	my $answer = $instance->{'origin'}{$origin}{'nexthop'}{'ipv4'}{$next_hop};
	# Format IPv4 prefix update
	print $channel "add,ipv4,".$prefix.",".((defined($answer) && $answer ne '') ? $answer:$next_hop)."\n";
    }
    # Statically configured IPv4 prefixes for this origin
    foreach my $prefix (keys %{$instance->{'origin'}{$origin}{'prefix'}{'ipv4'}}) {
	# Abort if we were told to
	last unless $instdata->{'evmon'}->running();
	# Map prefix to load balancer name
	# or direct A record data
	my $answer = $instance->{'origin'}{$origin}{'prefix'}{'ipv4'}{$prefix};
	# Format IPv4 prefix update
	print $channel "add,ipv4,".$prefix.",".((defined($answer) && $answer ne '') ? $answer:'')."\n";
    }

    # Abort if we were told to
    return unless $instdata->{'evmon'}->running();

    # Mark the end of IPv4 update cycle
    print $channel "end,ipv4\n";

    # Mark the beginning of IPv4 update cycle
    print $channel "begin,ipv6\n";

    # Get BGP table from Zebra/Quagga
    my @bgp_ipv6 = $instance->origin_collect_prefixes($instdata, $origin, 'ipv6');
    # Extract IPv6 prefix and next-hop information
    for(my $line = shift @bgp_ipv6; defined($line); $line = shift @bgp_ipv6) {
	# Abort if we were told to
	last unless $instdata->{'evmon'}->running();
	# IPv6 prefix can span from 1 to 3 lines
	# of raw 'show ipv6 bgp' command output,
	# so we perform regexp match across every
	# 3 consecutive lines.
	my $route = $line.(defined($bgp_ipv6[0]) ? $bgp_ipv6[0]:'').(defined($bgp_ipv6[1]) ? $bgp_ipv6[1]:'');
	# IPv6 BGP prefix components
	my ($prefix, $next_hop) = ($route =~ /^\*?>?[a-z]?([a-fA-F\d]{0,4}(?:\:(?!\:\:)[a-fA-F\d]{1,4}){0,6}(?:\:\:)?(?:[a-fA-F\d]{1,4}\:(?!\:\:)){0,6}[a-fA-F\d]{0,4}\/\d{1,2})\s+([a-fA-F\d]{0,4}(?:\:(?!\:\:)[a-fA-F\d]{1,4}){0,6}(?:\:\:)?(?:[a-fA-F\d]{1,4}\:(?!\:\:)){0,6}[a-fA-F\d]{0,4})\s+\d+\s+\d+\s+\d+/);
	next unless(defined($prefix) && $prefix ne '' &&
		    defined($next_hop) && $next_hop ne '');
	# Map next hop to load balancer name
	# or direct AAAA record data
	my $answer = $instance->{'origin'}{$origin}{'nexthop'}{'ipv6'}{$next_hop};
	# Format IPv6 prefix update
	print $channel "add,ipv6,".$prefix.",".((defined($answer) && $answer ne '') ? $answer:$next_hop)."\n";
    }
    # Statically configured IPv6 prefixes for this origin
    foreach my $prefix (keys %{$instance->{'origin'}{$origin}{'prefixes'}{'ipv6'}}) {
	# Abort if we were told to
	last unless $instdata->{'evmon'}->running();
	# Map prefix to load balancer name
	# or direct AAAA record data
	my $answer = $instance->{'origin'}{$origin}{'prefix'}{'ipv6'}{$prefix};
	# Format IPv6 prefix update
	print $channel "add,ipv6,".$prefix.",".((defined($answer) && $answer ne '') ? $answer:'')."\n";
    }

    # Abort if we were told to
    return unless $instdata->{'evmon'}->running();

    # Mark the end of IPv6 update cycle
    print $channel "end,ipv6\n";
}

sub origin_collect_prefixes($$$$) {
    my ($self, $instdata, $origin, $address_family) = @_;
    my $bgp;

    return unless(defined($origin) &&
		  defined($self->{'origin'}{$origin}{'neighbor'}) &&
		  defined($address_family) && $address_family =~ /^ipv[46]$/);

    # Neighbor is local Zebra/Quagga ?
    if($self->{'origin'}{$origin}{'neighbor'} eq 'local') {
	# Collect prefixes from local Zebra/Quagga
	$bgp = $self->local_collect_prefixes($address_family);
    } else {
	# Collect prefixes from remote Cisco/Zebra/Quagga
	$bgp = $self->remote_collect_prefixes($instdata, $origin, $address_family);
    }

    if(defined($bgp) && $bgp ne '') {
	$self->api->logging('LOG_INFO', "Nameserver backend %s: origin %s successfully collected new set of %s BGP prefixes",
					$self->{'instance'},
					$origin,
					$address_family eq 'ipv4' ? 'IPv4':'IPv6');
	return (split(/[\n\r]/, $bgp));
    }

    $self->api->logging('LOG_ERR', "Nameserver backend %s: origin %s failed to collect new set of %s BGP prefixes",
				       $self->{'instance'},
				       $origin,
				       $address_family eq 'ipv4' ? 'IPv4':'IPv6');

    return wantarray ? ():undef;
}

sub local_collect_prefixes($$) {
    my ($self, $address_family) = @_;
    my $bgp;

    if($address_family eq 'ipv4') {
	$bgp = `echo "sh ip bgp" | vtysh 2>&1`;
    } elsif($address_family eq 'ipv6') {
	$bgp = `echo "sh ipv6 bgp" | vtysh 2>&1`;
    }
    # Return output if no error has occured
    return (defined($bgp) && $bgp !~ /^exiting:\s+failed\s+to\s+connect/i) ? $bgp:undef;
}

sub remote_collect_prefixes($$$$) {
    my ($self, $instdata, $origin, $address_family) = @_;
    my $bgp;

    my $retries = $self->{'origin'}{$origin}{'remote_retries'};

    # Attempt to fetch prefixes exactly $retries times
    for(my $try = 0; !(defined($bgp) && $bgp ne "") && ($try < $retries); $try++) {
	# Begin new telnet session to the neighbor
	my $telnet = $self->remote_connect($instdata, $origin);
	if(defined($telnet)) {
	    # Request IPv4 prefixes
	    if($address_family eq 'ipv4') {
		$bgp = $self->remote_command($telnet, "sh ip bgp");
	    # Request IPv6 prefixes
	    } elsif($address_family eq 'ipv6') {
		$bgp = $self->remote_command($telnet, "sh ipv6 bgp");
	    }
	    # Disconnect from neighbor
	    $self->remote_disconnect($telnet, $origin);
	}
    }

    # Return output if no error has occured
    return (defined($bgp) && $bgp ne '') ? $bgp:undef;
}

sub remote_connect($$$) {
    my ($self, $instdata, $origin) = @_;
    my $res;

    # Create telnet client instance
    my $telnet = Net::Telnet->new(Port => $self->{'origin'}{$origin}{'port'},
				  Prompt => '/\w*[>#]\s$/',
				  Timeout => $self->{'origin'}{$origin}{'remote_timeout'},
				  Errmode => 'return');
    unless($telnet) {
	$self->api->logging('LOG_DEBUG', "Nameserver backend %s: failed to initialize BGP prefix collector for origin %s",
					 $self->{'instance'},
					 $origin);
	return undef;
    }

    # Open telnet connection
    $res = $telnet->open($self->{'origin'}{$origin}{'neighbor'});
    unless($res) {
	$self->api->logging('LOG_DEBUG', "Nameserver backend %s: origin %s's BGP prefix collector failed to connect to BGP neighbor %s",
					 $self->{'instance'},
					 $origin,
					 $self->{'origin'}{$origin}{'neighbor'});
	return undef;
    }

    # Wait for initial prompt that can either be
    # a username, a password or a command prompt
    my ($prematch, $match) = $telnet->waitfor(Match => '/(([Ll]ogin|[Uu]ser(name)?|[Pp]ass(w(or)?d)?):|\w*[>#])\s$/',
					      Timeout => $self->{'origin'}{$origin}{'remote_timeout'});
    unless($match) {
	$self->api->logging('LOG_DEBUG', "Nameserver backend %s: origin %s's BGP prefix collector timed out while waiting for neighbor %s",
					 $self->{'instance'},
					 $origin,
					 $self->{'origin'}{$origin}{'neighbor'});
	# Disconnect from router/Quagga/Zebra
	$self->remote_disconnect($telnet, $origin);
	return undef;
    }

    # Neighbor asked for username ?
    if($match =~ /[Ll]ogin|[Uu]ser(name)?/) {
	# Log in, if credentials are defined
	unless(defined($self->{'origin'}{$origin}{'username'}) &&
	       $self->{'origin'}{$origin}{'username'} ne '') {
	    $self->api->logging('LOG_DEBUG', "Nameserver backend %s: origin %s's BGP neighbor %s asks for username, but none is configured",
					     $self->{'instance'},
					     $origin,
					     $self->{'origin'}{$origin}{'neighbor'});
	    # Disconnect from router/Quagga/Zebra
	    $self->remote_disconnect($telnet, $origin);
	    return undef;
	}
	# Send username
	$telnet->print($self->{'origin'}{$origin}{'username'});
	# Wait next prompt
	($prematch, $match) = $telnet->waitfor(Match => '/([Pp]ass(w(or)?d)?:|\w*[>#])\s$/',
					       Timeout => $self->{'origin'}{$origin}{'remote_timeout'});
	unless($match) {
	    $self->api->logging('LOG_DEBUG', "Nameserver backend %s: origin %s's BGP prefix collector timed out while waiting for neighbor %s",
					     $self->{'instance'},
					     $origin,
					     $self->{'origin'}{$origin}{'neighbor'});
	    # Disconnect from router/Quagga/Zebra
	    $self->remote_disconnect($telnet, $origin);
	    return undef;
	}
    }

    # Neighbor asks for password ?
    if($match =~ /[Pp]ass(w(or)?d)?/) {
	# Log in, if credentials are defined
	unless(defined($self->{'origin'}{$origin}{'password'}) &&
	       $self->{'origin'}{$origin}{'password'} ne '') {
	    $self->api->logging('LOG_DEBUG', "Nameserver backend %s: origin %s's BGP neighbor %s asks for password, but none is configured",
					     $self->{'instance'},
					     $origin,
					     $self->{'origin'}{$origin}{'neighbor'});
	    # Disconnect from router/Quagga/Zebra
	    $self->remote_disconnect($telnet, $origin);
	    return undef;
	}
	# Send password
	$telnet->print($self->{'origin'}{$origin}{'password'});
	# Wait next prompt
	($prematch, $match) = $telnet->waitfor(Match => '/([Pp]ass(w(or)?d)?:|\w*[>#])\s$/',
					       Timeout => $self->{'origin'}{$origin}{'remote_timeout'});
	unless($match) {
	    $self->api->logging('LOG_DEBUG', "Nameserver backend %s: origin %s's BGP prefix collector timed out while waiting for neighbor %s",
					     $self->{'instance'},
					     $origin,
					     $self->{'origin'}{$origin}{'neighbor'});
	    # Disconnect from router/Quagga/Zebra
	    $self->remote_disconnect($telnet, $origin);
	    return undef;
	}
	# If we got password prompt again,
	# password we sent is wrong
	if($match =~ /[Pp]ass(w(or)?d)?/) {
	    $self->api->logging('LOG_DEBUG', "Nameserver backend %s: wrong password for origin %s's BGP neighbor %s",
					     $self->{'instance'},
					     $origin,
					     $self->{'origin'}{$origin}{'neighbor'});
	    # Disconnect from router/Quagga/Zebra
	    $self->remote_disconnect($telnet, $origin);
	    return undef;
	}
    }

    # At this point we should have command prompt
    unless($match =~ /\w*[>\#]\s$/) {
	$self->api->logging('LOG_DEBUG', "Nameserver backend %s: unexpected input from origin %s's BGP neighbor %s",
					 $self->{'instance'},
					 $origin,
					 $self->{'origin'}{$origin}{'neighbor'});
	    # Disconnect from router/Quagga/Zebra
	$self->remote_disconnect($telnet, $origin);
	return undef;
    }

    # Do not paginate output
    $telnet->print("terminal length 0");
    # Wait for the final prompt
    # before we can issue commands
    $res = $telnet->waitfor(Match => $telnet->prompt,
			    Timeout => $self->{'origin'}{$origin}{'remote_timeout'});
    unless($res) {
	$self->api->logging('LOG_DEBUG', "Nameserver backend %s: origin %s's BGP prefix collector timed out while waiting for neighbor %s",
					 $self->{'instance'},
					 $origin,
					 $self->{'origin'}{$origin}{'neighbor'});
	    # Disconnect from router/Quagga/Zebra
	$self->remote_disconnect($telnet, $origin);
	return undef;
    }

    $self->api->logging('LOG_DEBUG', "Nameserver backend %s: origin %s's BGP prefix collector connected to neighbor %s",
				     $self->{'instance'},
				     $origin,
				     $self->{'origin'}{$origin}{'neighbor'});

    return $telnet;
}

sub remote_disconnect($$$) {
    my ($self, $telnet, $origin) = @_;

    return unless(defined($telnet) && defined($origin));

    # Close telnet connection
    $telnet->close;

    $self->api->logging('LOG_DEBUG', "Nameserver backend %s: origin %s's BGP prefix collector disconnected from neighbor %s",
				     $self->{'instance'},
				     $origin,
				     $self->{'origin'}{$origin}{'neighbor'});
}

sub remote_command($$;@) {
    my $self = shift;
    my $telnet = shift;

    my $input = join(' ', @_);
    return undef unless(defined($input) && $input ne '');

    # Send CLI command
    $telnet->print($input);

    my $output = '';

    # Collect command output
    for(my $line = $telnet->getline;
	defined($line) && $line !~ /^\w*[>#]\s$/;
	$line = $telnet->getline) {
	# Result will be a single multiline string
	$output .= $line;
    }

    return $output;
}

1;

