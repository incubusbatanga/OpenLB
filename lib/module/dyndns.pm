#
# module::dyndns.pm
#
# Copyright (c) 2014 Marko Dinic <marko@yu.net>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.
#

package module::dyndns;

##############################################################################################

use strict;
use warnings;

##############################################################################################

use Net::DNS;
use Config::ContextSensitive qw(:macros);

##############################################################################################

use api::module;

##############################################################################################

our @ISA = qw(api::module);

##############################################################################################

our $CONF_TEMPLATE = SECTION(
    DIRECTIVE('nameserver', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$SECTION' => { 'nameserver' => '$VALUE' } }))),
    DIRECTIVE('domain', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$SECTION' => { 'domain' => '$VALUE' } }))),
    DIRECTIVE('update_record', SKIP, 
	REQUIRE(DIRECTIVE('from', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$SECTION' => { 'lb' => { '$VALUE' => { 'update' => '$ARG[1]' } } } }))))
    ),
    DIRECTIVE('update_interval', ARG(CF_INTEGER, STORE(TO 'MODULE', KEY { '$SECTION' => { 'interval' => '$VALUE' } }), DEFAULT '3')),
    DIRECTIVE('update_timeout', ARG(CF_INTEGER, STORE(TO 'MODULE', KEY { '$SECTION' => { 'timeout' => '$VALUE' } }), DEFAULT '3')),
    DIRECTIVE('tsig_key', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$SECTION' => { 'key_name' => '$VALUE' } })),
			  ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$SECTION' => { 'key_hash' => '$VALUE' } })))
);

##############################################################################################

sub register() {
    return $CONF_TEMPLATE;
}

sub initialize($$) {
    my ($self, $instdata) = @_;

    $instdata->{'changed'} = 0;
    $instdata->{'failed'} = 0;

    return $self->reinitialize($instdata);
}

sub reinitialize($$) {
    my ($self, $instdata) = @_;


    # Schedule regular DNS updates
    $instdata->{'updater'} = defined($instdata->{'updater'}) ?
				$self->api->modify_timer_event($instdata->{'updater'},
							       'interval' => $self->{'interval'},
							       'args' => [ $self, $instdata ],
							       'timeout' => $self->{'timeout'}):
				$self->api->create_timer_event('interval' => $self->{'interval'},
							       'handler' => \&send_periodic_updates,
							       'args' => [ $self, $instdata ],
							       'timeout' => $self->{'timeout'});

    return $instdata;
}

sub process($$$$$$$$) {
    my ($self, $instdata, $lb, $seq, $preference, $input, $ipv4, $ipv6) = @_;

    # At least one address family must be defined
    # and we need only the first, most preferred
    # host. A new sequence number per load balancer
    # marks the beginning of a new dataset.
    return unless(((defined($ipv4) && $ipv4 ne '') ||
		   (defined($ipv6) && $ipv6 ne '')) &&
		  ((!defined($instdata->{'seq'}{$lb}) ||
		   $seq > $instdata->{'seq'}{$lb})));

    # Remember our current sequence
    $instdata->{'seq'}{$lb} = $seq;

    # Update only if record data have changed
    return unless((defined($preference) &&
		    (!defined($instdata->{'lb'}{$lb}{'pref'}) ||
		     $preference != $instdata->{'lb'}{$lb}{'pref'})) ||
		  (defined($ipv4) &&
		    (!defined($instdata->{'lb'}{$lb}{'ipv4'}) ||
		     $ipv4 ne $instdata->{'lb'}{$lb}{'ipv4'})) ||
		  (defined($ipv6) &&
		    (!defined($instdata->{'lb'}{$lb}{'ipv6'}) ||
		     $ipv6 ne $instdata->{'lb'}{$lb}{'ipv6'})));

    # Store received data
    delete $instdata->{'lb'}{$lb};
    $instdata->{'lb'}{$lb}{'ipv4'} = $ipv4;
    $instdata->{'lb'}{$lb}{'ipv6'} = $ipv6;
    $instdata->{'lb'}{$lb}{'pref'} = $preference;
    # Note that changes have occured
    $instdata->{'lb'}{$lb}{'changed'} = 1;
    # Explicitly return nothing
    return;
}

##############################################################################################

sub send_periodic_updates($$$) {
    my ($timer, $instance, $instdata) = @_;

    # Create nameserver object
    my $nameserver = Net::DNS::Resolver->new();
    unless(defined($nameserver)) {
	$instance->api->logging('LOG_ERR', "Dynamic DNS backend %s init: failed to initialize session to the nameserver %s",
					   $instance->{'instance'},
					   $instance->{'nameserver'});
        return;
    }

    # Add target nameservers
    $nameserver->nameservers($instance->{'nameserver'});
    # Create new update packet
    my $update_packet = Net::DNS::Update->new($instance->{'domain'});
    return unless defined($update_packet);

    # Pack data from all load balancers
    foreach my $lb (keys %{$instdata->{'lb'}}) {

	# Pack data from this load balancer only if
	# there are pending changes or last known
	# state was failure to deliver update
        next unless(defined($instance->{'lb'}{$lb}{'update'}) && 
		    $instance->{'lb'}{$lb}{'update'} ne "" &&
		    ($instdata->{'lb'}{$lb}{'changed'} ||
		     $instdata->{'failed'}));

	# This is a FQDN that will get updated
	my $fqdn = $instance->{'lb'}{$lb}{'update'}.'.'.$instance->{'domain'};

	# Remove existing DNS record
	$update_packet->push(update => rr_del($fqdn));

	# Add new records only if preference is > 0
	if($instdata->{'lb'}{$lb}{'pref'} > 0) {

	    my $ipv4 = $instdata->{'lb'}{$lb}{'ipv4'};
	    my $ipv6 = $instdata->{'lb'}{$lb}{'ipv6'};

	    if(defined($ipv4) && $ipv4 ne '') {
		# Add new A record to the update packet
		# TTL will be equal to update interval
		$update_packet->push(update => rr_add($fqdn." ".$instance->{'interval'}." A ".$ipv4));
	    }

	    if(defined($ipv6) && $ipv6 ne '') {
	        # Add new AAAA record to the update packet
		# TTL will be equal to update interval
		$update_packet->push(update => rr_add($fqdn." ".$instance->{'interval'}." AAAA ".$ipv6));
	    }
	}

	# If TSIG key is defined
	if(defined($instance->{'key_name'}) &&
	   defined($instance->{'key_hash'})) {
	    # ... sign the update
	    $update_packet->sign_tsig($instance->{'key_name'},
				      $instance->{'key_hash'});
	}

	# Data is now up to date
	$instdata->{'lb'}{$lb}{'changed'} = 0;

    }

    # Do not send update if it has no RRs
    # (ie. there were no changes whatsoever,
    # thus the update packet remains empty)
    return unless $update_packet->authority;

    $instance->api->logging('LOG_DEBUG', "Dynamic DNS backend %s: sending update to nameserver %s",
					 $instance->{'instance'},
					 $instance->{'nameserver'});

    # Reply packet ID has to match
    # our update packet's ID
    my $id = $update_packet->header->id;

    # Send update asynchronosly
    my $sock = $nameserver->bgsend($update_packet);
    # Check for failure
    unless(defined($sock)) {
	# Log failure
	$instance->api->logging('LOG_WARNING', "Dynamic DNS backend %s: failed to send update to nameserver %s",
					       $instance->{'instance'},
					       $instance->{'nameserver'});
	# Mark failure
	$instdata->{'failed'}++;
	return;
    }

    # Monitor socket for reply
    $instance->api->create_io_event('file' => $sock,
				    'op' => 'r',
				    'handler' => \&receive_response,
				    'args' => [ $instance, $instdata, $nameserver, $id ],
				    'timeout' => $instance->{'timeout'},
				    'on_timeout' => \&timeout_handler,
				    'expire_in' => $instance->{'timeout'},
				    'on_expiry' => \&timeout_handler);

    # Explicitly return nothing
    return;
}

sub receive_response($$$$$) {
    my ($sock, $instance, $instdata, $nameserver, $id) = @_;

    # Read response from the nameserver.
    # It must match update packet's ID.
    my $reply = $nameserver->bgread($sock);
    return unless(defined($reply) && $reply->header->id == $id);

    # No need to monitor this socket any longer
    $instance->api->destroy_io_event($sock);

    # Check if operation completed successfully
    my $rcode = $reply->header->rcode;
    if($rcode eq "NOERROR") {

	# Reset failure marker
	$instdata->{'failed'} = 0;

	$instance->api->logging('LOG_INFO', "Dynamic DNS backend %s: nameserver %s reports: update successful",
					    $instance->{'instance'},
					    $reply->answerfrom);

    } else {

	# Set failure marker
	$instdata->{'failed'}++;

	$instance->api->logging('LOG_INFO', "Dynamic DNS backend %s: nameserver %s reports: %s",
					    $instance->{'instance'},
					    $reply->answerfrom,
					    $rcode);

    }

    # Explicitly return nothing
    return;
}

sub timeout_handler($$$) {
    my ($sock, $instance, $instdata) = @_;

    $instance->api->logging('LOG_WARNING', "Dynamic DNS backend %s: nameserver %s update timed out",
					   $instance->{'instance'},
					   $instance->{'nameserver'});
    # Mark failure
    $instdata->{'failed'}++;

    # Explicitly return nothing
    return;
}

1;
