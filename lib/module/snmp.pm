#
# module::snmp.pm
#
# Copyright (c) 2014 Marko Dinic <marko@yu.net>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.
#

package module::snmp;

##############################################################################################

use strict;
use warnings;

##############################################################################################

use SNMP;
use Config::ContextSensitive qw(:macros);

##############################################################################################

use api::module;

##############################################################################################

our @ISA = qw(api::module);

##############################################################################################

my $CONF_TEMPLATE = SECTION(
    DIRECTIVE('host', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$SECTION' => { 'host' => '$VALUE' } }))),
    DIRECTIVE('community', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$SECTION' => { 'community' => '$VALUE' } }))),
    DIRECTIVE('table', SECTION_NAME, ALLOW(
	DIRECTIVE('size', ARG(CF_INTEGER, STORE(TO 'MODULE', KEY { '$SECTION' => { 'table' => { '$NESTED_SECTION' => { 'size' => '$VALUE' } } } }))),
	DIRECTIVE('size_from', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$SECTION' => { 'table' => { '$NESTED_SECTION' => { 'size_from' => '$VALUE' } } } })))
    ), SECTION(
	DIRECTIVE('refresh_interval', ARG(CF_INTEGER, STORE(TO 'MODULE', KEY { '$PARENT_SECTION' => { 'table' => { '$SECTION' => { 'refresh_interval' => '$VALUE' } } } }))),
	DIRECTIVE('index', SKIP, REQUIRE(DIRECTIVE('matching', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$PARENT_SECTION' => { 'table' => { '$SECTION' => { 'idx' => { '$ARG[1]' => '$VALUE' } } } } })))))
    )),
    DIRECTIVE('/^(gauge|counter)$/', SKIP, ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$SECTION' => { 'oid' => { '$ARG[1]' => { 'fmt' => '$VALUE', 'type' => '$DIRECTIVE', 'wrapcnt' => 0 } } } }))),
    DIRECTIVE('field', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$SECTION' => { 'fields' => [ '$VALUE' ] } })), REQUIRE(
	DIRECTIVE('/^([=~]|set|avg)$/', ARG(CF_LINE, STORE(TO 'MODULE', KEY { '$SECTION' => { 'field' => { '$ARG[1]' => { 'oper' => '$DIRECTIVE', 'expr' => '$VALUE' } } } })))
    )),
    DIRECTIVE('check_interval', ARG(CF_INTEGER, STORE(TO 'MODULE', KEY { '$SECTION' => { 'check_interval' => '$VALUE' } }), DEFAULT '10')),
    DIRECTIVE('check_timeout', ARG(CF_INTEGER, STORE(TO 'MODULE', KEY { '$SECTION' => { 'check_timeout' => '$VALUE' } }), DEFAULT '2')),
    DIRECTIVE('check_retries', ARG(CF_INTEGER, STORE(TO 'MODULE', KEY { '$SECTION' => { 'check_retries' => '$VALUE' } }), DEFAULT '5'))
);

##############################################################################################

our $WRAP32 = 0xffffffff + 1;

##############################################################################################

sub register() {
    return $CONF_TEMPLATE;
}

sub daemonize($) {
    my $self = shift;

    my $instdata = {};

    $self->set_initialize_timeout($self->{'check_timeout'});

    return $instdata;
}

sub initialize($$) {
    my ($self, $instdata) = @_;

    # Initialize SNMP MIB
    SNMP::initMib();

    # Set initial timestamp
    $instdata->{'timestamp'} = time();

    # (Re)initialize instance data
    return $self->reinitialize($instdata);
}

sub reinitialize($$) {
    my ($self, $instdata) = @_;

    $self->set_reinitialize_timeout($self->{'check_timeout'});

    # Do some sanity checks ...

    foreach my $table (keys %{$self->{'table'}}) {
	# Go through table's indexes
	foreach my $index_name (keys %{$self->{'table'}{$table}{'idx'}}) {
	    # Look for index with the same name in other tables
	    foreach my $other_table (keys %{$self->{'table'}}) {
		# Skip ourselves
		next if $other_table eq $table;
		# Configured index names must be unique
		if(defined($self->{'table'}{$other_table}{'idx'}{$index_name})) {
		    $self->api->logging('LOG_ERR', "SNMP collector %s: host %s already has index named %s in table %s. Index names must be unique.",
						   $self->{'instance'},
						   $self->{'host'},
						   $index_name,
						   $table);
		    return undef;
		}
	    }
	}
    }

    # Make sure host is in IP format
    $instdata->{'ipv4'} = $self->api->get_host_by_name($self->{'host'}, 'ipv4');
    $instdata->{'ipv6'} = $self->api->get_host_by_name($self->{'host'}, 'ipv6');
    $instdata->{'host'} = defined($instdata->{'ipv6'}) ?
				    $instdata->{'ipv6'}:$instdata->{'ipv4'};

    # Init index table
    $instdata->{'indexes'} = {};

    # Go through all configured tables
    foreach my $table_oid (keys %{$self->{'table'}}) {
	# How often the table should be re-read ?
	my $refresh_interval = defined($self->{'table'}{$table_oid}{'refresh_interval'}) ?
					    $self->{'table'}{$table_oid}{'refresh_interval'}:300;
	# Create periodic event for re-reading for each table
	$instdata->{'table'}{$table_oid}{'collector'} = defined($instdata->{'table'}{$table_oid}{'collector'}) ?
		$self->api->modify_timer_event($instdata->{'table'}{$table_oid}{'collector'},
					       'interval' => $refresh_interval,
					       'args' => [ $self, $instdata, $table_oid ],
					       'timeout' => $self->{'check_interval'}):
		$self->api->create_timer_event('interval' => $refresh_interval,
					       'handler' => \&refresh_table_indexes,
					       'args' => [ $self, $instdata, $table_oid ],
					       'timeout' => $self->{'check_interval'},
					       'on_timeout' => sub {
						    my ($timer, $instance, $instdata, $table_oid) = @_;
						    $instance->api->logging('LOG_INFO', "SNMP collector %s: host %s down",
											$instance->{'instance'},
											$instance->{'host'});
						    # Return 'host down' status
						    return $instance->down;
						});
    }

    # Create periodic event for data retrieval
    $instdata->{'collector'} = defined($instdata->{'collector'}) ?
	    $self->api->modify_timer_event($instdata->{'collector'},
					   'interval' => $self->{'check_interval'},
					   'args' => [ $self, $instdata ],
					   'timeout' => $self->{'check_interval'}):
	    $self->api->create_timer_event('interval' => $self->{'check_interval'},
					   'delay' => ($self->{'check_timeout'} * $self->{'check_retries'}) +
						      scalar(keys %{$self->{'table'}}) + 1,
					   'handler' => \&collect_oid_data,
					   'args' => [ $self, $instdata ],
					   'timeout' => $self->{'check_interval'},
					   'on_timeout' => sub {
						my ($timer, $instance, $instdata) = @_;
						# Report the host is down
						$instance->api->logging('LOG_INFO', "SNMP collector %s: host %s down",
										    $instance->{'instance'},
										    $instance->{'host'});
						# Return 'host down' status
						return $instance->down;

					   });

    return $instdata;
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

sub refresh_table_indexes($$$$) {
    my ($timer, $instance, $instdata, $table_oid) = @_;
    my @varbindlist = ();
    my %asn1 = ();
    my %indexes = ();

    # Create SNMP session
    my $snmp = SNMP::Session->new(DestHost => $instdata->{'host'},
				  Version => 2,
				  Community => $instance->{'community'},
				  Timeout => $instance->{'check_timeout'} * 1000000,
				  Retries => $instance->{'check_retries'},
				  RetryNoSuch => 1);

    unless(defined($snmp) && ref($snmp) eq 'SNMP::Session') {
	$instance->api->logging('LOG_INFO', "SNMP collector %s: failed to create SNMP session",
					    $instance->{'instance'});
	return;
    }

    my %params = (noindexes => 1, columns => [ $table_oid ]);

    # Statically configured table size ?
    if(defined($instance->{'table'}{$table_oid}{'size'}) &&
       $instance->{'table'}{$table_oid}{'size'} > 0) {

	# Set the number of entries to walk to static value
	$params{repeatcount} = $instance->{'table'}{$table_oid}{'size'};

    # Get table size from an OID
    } elsif(defined($instance->{'table'}{$table_oid}{'size_from'}) &&
	    $instance->{'table'}{$table_oid}{'size_from'} ne '') {

	# Fetch table size
	my ($size) = $snmp->get(SNMP::VarList->new([$instance->{'table'}{$table_oid}{'size_from'}]));
	unless(defined($size) && $size =~ /^\d+$/) {
	    # Report the host is down
	    $instance->api->logging('LOG_INFO', "SNMP collector %s: host %s down",
						$instance->{'instance'},
						$instance->{'host'});
	    # Close SNMP session
	    undef $snmp;
	    # Return 'host down' status
	    return $instance->down;
	}

	# Set the number of entries to walk to retrieved table size
	$params{repeatcount} = $size;

    }

    # Get table contents (walk the table)
    my $table = $snmp->gettable($table_oid, %params);

    # Close SNMP session
    undef $snmp;

    # If table walk failed ...
    unless(defined($table) && scalar(keys %{$table}) > 0) {
	# ... report the host is down
	$instance->api->logging('LOG_INFO', "SNMP collector %s: host %s down",
					    $instance->{'instance'},
					    $instance->{'host'});
	# Return 'host down' status
	return $instance->down;
    }

    # Loop through all configured indexes for current table
    foreach my $index_name (keys %{$instance->{'table'}{$table_oid}{'idx'}}) {
	# Regexp matching our index
	my $regexp = $instance->{'table'}{$table_oid}{'idx'}{$index_name};
	# Search for index whose value
	# matches the configured regexp
	index_search: {
	    foreach my $index (keys %{$table}) {
		foreach my $value (values %{$table->{$index}}) {
		    if($value =~ /$regexp/i) {
			# Store index under configured name
			$indexes{$index_name} = $index;
			$instance->api->logging('LOG_DEBUG', "SNMP collector %s: index %s matching \"%s\" in table %s is %u",
							     $instance->{'instance'},
							     $index_name,
							     $instance->{'table'}{$table_oid}{'idx'}{$index_name},
							     $table_oid,
							     $index);
			last index_search;
		    }
		}
	    }
	}

	# ALL configured indexes must be found in the table
	unless(defined($indexes{$index_name}) && $indexes{$index_name} ne '') {
	    # If one index is missing, flush new index table
	    %indexes = ();
	    # Complain :)
	    $instance->api->logging('LOG_WARNING', "SNMP collector %s: host %s doesn't have any index matching \"%s\" in table %s",
						   $instance->{'instance'},
						   $instance->{'host'},
						   $instance->{'table'}{$table_oid}{'idx'}{$index_name},
						   $table_oid);
	    # Don't go any further
	    last;
	}
    }

    # Retain previous table, OIDs and variables
    # unless we have a valid new index table
    return unless(scalar(keys %indexes) > 0);

    # Make new table active
    foreach my $index_name (keys %indexes) {
	# Merge these indexes into the index table
	$instdata->{'indexes'}{$index_name} = $indexes{$index_name};
    }

    $instance->api->logging('LOG_INFO', "SNMP collector %s: table %s refreshed",
							 $instance->{'instance'},
							 $table_oid);

    # On every table update do a full xlat of all defined OIDs.
    # This should be neccessary only once all tables have been
    # updated, but since they can be updated on different
    # schedules, we have to full xlat after each table.

    # Prepare the list of OIDs to request from the device
    foreach my $oid_name (keys %{$instance->{'oid'}}) {
	# Append indexes fetched from tables to OIDs, if neccessary
	my $oid = $instance->xlat_oid($instdata, $oid_name);
	# ALL configured OIDs have to be xlated
	unless(defined($oid) && $oid ne '') {
	    # If one OID is missing/invalid, flush new OID table
	    %asn1 = ();
	    # Complain :)
	    $instance->api->logging('LOG_ERR', "SNMP collector %s: data source %s defined invalid OID \"%s\"",
					       $instance->{'instance'},
					       $oid_name,
					       $instance->{'oid'}{$oid_name}{'fmt'});
	    # End xlat run
	    last;
	}
	# Store xlated ASN1 form of this OID
	$asn1{$oid_name} = $oid;
	# Append this OID to the list of OIDs
	# that we will request from the device
	push @varbindlist, SNMP::Varbind->new([$oid]);

	$instance->api->logging('LOG_DEBUG', "SNMP collector %s: xlat %s to %s",
					     $instance->{'instance'},
					     $instance->{'oid'}{$oid_name}{'fmt'},
					     $oid);
    }

    # If we have a new OID table ...
    if(scalar(keys %asn1) > 0 && scalar(@varbindlist) > 0) {
	# Set new OID-name-to-ASN1 mapping table
	$instdata->{'asn'} = \%asn1;
	# Set new var bind list
	$instdata->{'varbindlist'} = \@varbindlist;
    }

    return;
}

sub collect_oid_data($$$) {
    my ($timer, $instance, $instdata) = @_;
    my %snmp_data = ();
    my @values  = ();

    # Save last cycle's timestamp
    $instdata->{'last_timestamp'} = $instdata->{'timestamp'};
    # Get current timestamp
    $instdata->{'timestamp'} = time();
    # Calculate interval between current and previous check
    # for <metric> per second calculations.
    $instdata->{'delta_t'} = $instdata->{'timestamp'} - $instdata->{'last_timestamp'};

    # Create SNMP session
    my $snmp = SNMP::Session->new(DestHost => $instdata->{'host'},
				  Version => 2,
				  Community => $instance->{'community'},
				  Timeout => $instance->{'check_timeout'} * 1000000,
				  Retries => $instance->{'check_retries'},
				  UseNumeric => 1,
				  RetryNoSuch => 1);

    unless(defined($snmp) && ref($snmp) eq 'SNMP::Session') {
	$instance->api->logging('LOG_INFO', "SNMP collector %s: failed to create SNMP session",
					    $instance->{'instance'});
	return;
    }

    # Get a copy of varbind list to be requested
    my @varbindlist = @{$instdata->{'varbindlist'}};
    # Perform get()s in small chunks
    while(@varbindlist) {
	# Next chunk of the list to be requested
	my @request_vars = splice(@varbindlist, 0, 10);
	# Get SNMP data from the device
	my @chunk = $snmp->get(SNMP::VarList->new(@request_vars));
	unless(@chunk) {
	    # Report the host is down
	    $instance->api->logging('LOG_INFO', "SNMP collector %s: host %s down",
						$instance->{'instance'},
						$instance->{'host'});
	    # Return 'host down' status
	    return $instance->down;
	}
	# Merge received data into a single hash
	for(my $i = 0; $i < scalar(@request_vars); $i++) {
	    my $varbind = $request_vars[$i];
	    # Make sure OID is in numeric form
	    my $oid = ($varbind->tag =~ /[^\.\d]/) ?
			SNMP::translateObj($varbind->tag):$varbind->tag;
	    # If OID is a table, instance id
	    # will be given separately ...
	    my $inst = $varbind->iid;
	    if(defined($inst) && $inst ne '') {
		# Put base oid and instance id together
		$oid .= '.'.$varbind->iid;
	    }
	    # Store retrieved data for later use in record field expressions
	    # unless value we got is NOSUCHINSTANCE, in which case store undef
	    $snmp_data{$oid} = ($chunk[$i] =~ /^nosuchinstance$/i) ? undef:$chunk[$i];
	}
    }

    # Close SNMP session
    undef $snmp;

    # Sort retrieved values in the same order
    # fields are defined in the configuration
    foreach my $field_name (@{$instance->{'fields'}}) {
	my $value =  $instance->get_field($instdata, $field_name, \%snmp_data);
	unless(defined($value)) {
	    $instance->api->logging('LOG_ERR', "SNMP collector %s: field %s defined invalid operator \"%s\" or expression \"%s\"",
					       $instance->{'instance'},
					       $field_name,
					       $instance->{'field'}{$field_name}{'oper'},
					       $instance->{'field'}{$field_name}{'expr'});
	    return;
	}
	# Store field value in the array
	# from which the collector data will
	# be formatted and sent to OpenLB
	push @values, $value;
    }

    my @addr = $instance->host($instdata);
    shift @addr unless defined($addr[0]);
    pop @addr unless defined($addr[$#addr]);

    # We must have at least one address
    unless(@addr) {
	$instance->api->logging('LOG_ERR', "SNMP collector %s: couldn't resolve any address for this host",
					   $instance->{'instance'});
	return;
    }

    # Done if we have no data to deliver,
    unless(@values) {
	$instance->api->logging('LOG_INFO', "SNMP collector %s: no data collected from host %s on this run",
					    $instance->{'instance'},
					    $instance->{'host'});
	return;
    }

    # Send serialized collected data to the load balancer
    $instance->api->logging('LOG_INFO', "SNMP collector %s: host %s up, ".join('=%s, ', @{$instance->{'fields'}})."=%s",
					$instance->{'instance'},
					join(', ', @addr),
					@values);

    # Return 'host up' status with collected dataset
    return $instance->up(@values);
}

##############################################################################################

sub get_field($$$$) {
    my ($self, $instdata, $field_name, $data) = @_;

    # Xlat variables and evaluate expression
    my $value = $self->xlat_expr($instdata, $self->{'field'}{$field_name}{'expr'}, $data);
    return undef unless defined($value);

    # What to do with value produced from expression
    my $oper = $self->{'field'}{$field_name}{'oper'};

    # Equality operator
    if($oper eq '=' || $oper eq 'set') {

	return $value;

    # Average operator
    } elsif($oper eq '~' || $oper eq 'avg') {

	my $avg = 0;
	# Previous field value
	my $prev = defined($instdata->{'field'}{$field_name}{'prev'}) ?
			    $instdata->{'field'}{$field_name}{'prev'}:$value;

	# Time interval between 2 checks
	if($instdata->{'delta_t'} > 0) {
	    # Calculate average field value in time
	    # between this and previous check.
	    $avg = ($value - $prev) / $instdata->{'delta_t'};
	}
	# Remember previous field value
	$instdata->{'field'}{$field_name}{'prev'} = $value;

	$self->api->logging('LOG_DEBUG', "SNMP collector %s: average(%s) is (%u - %u) / %u which evaluates to %u",
					 $self->{'instance'},
					 $field_name,
					 $value,
					 $prev,
					 $instdata->{'delta_t'},
					 $avg);

	return int($avg);

    }

    return undef;
}

sub xlat_oid($$$) {
    my ($self, $instdata, $oid_name) = @_;

    my $oid = $self->{'oid'}{$oid_name}{'fmt'};
    return undef unless defined($oid);

    # Replace $index_name with its oid
    while($oid =~ /\$([^\$\s\n\r]+)/g) {
	# Our match is the name of the variable
	# referencing one of our table indexes
	my $varname = $1;
	# Get table index referenced by the variable
	my $index = $instdata->{'indexes'}{$varname};
	# If index is valid ...
	if(defined($index) && $index ne '') {
	    # ... substitute variable name with
	    # index's numeric value
	    $oid =~ s/(\$$varname)/$index/g;
	}
    }
    return $oid;
}

sub xlat_expr($$$$) {
    my ($self, $instdata, $expr, $data) = @_;
    my $orig_expr = $expr;

    # Replace $oid_names with oid values
    while($expr =~ /\$([^\$\s\n\r]+)/g) {
	# Our match is the name of the variable
	# referencing one of our data sources
	my $varname = $1;
	# Get fully qualified oid in asn1 format
	my $oid = $instdata->{'asn'}{$varname};
	if(defined($oid)) {
	    my $value = $data->{$oid};
	    if(defined($value)) {
		if($self->{'oid'}{$varname}{'type'} eq 'counter') {
		    # Get previous counter value
		    my $prev = $instdata->{'oid'}{$varname}{'prev'};
		    # Remember current counter value
		    $instdata->{'oid'}{$varname}{'prev'} = $value;
		    # Compensate for 32-bit counter wrap
		    if(defined($prev) && ($value < $prev)) {
			# Count how many times the counter
			# wrapped around 32-bit max value
			$instdata->{'oid'}{$varname}{'wrapcnt'}++;
		    }
		    $value += defined($instdata->{'oid'}{$varname}{'wrapcnt'}) ?
				($WRAP32 * $instdata->{'oid'}{$varname}{'wrapcnt'}):0;

		}
		# Replace $oid_name with actual retrieved value
		$expr =~ s/(\$$varname)/$value/g;
	    }
	}
    }

    # Evaluate the expression
    my $result;
    eval '$result='.$expr;

    $self->api->logging('LOG_DEBUG', "SNMP collector %s: xlat (%s) to (%s) which evaluates to %u",
				     $self->{'instance'},
				     $orig_expr,
				     $expr,
				     $result);

    return $result;
}

1;
