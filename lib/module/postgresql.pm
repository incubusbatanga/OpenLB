#
# module::postgresql.pm
#
# Copyright (c) 2014 Marko Dinic <marko@yu.net>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.
#

package module::postgresql;

##############################################################################################

use strict;
use warnings;

##############################################################################################

use Pg;
use Config::ContextSensitive qw(:macros);

##############################################################################################

use api::module;

##############################################################################################

our @ISA = qw(api::module);

##############################################################################################

my $CONF_TEMPLATE = SECTION(
    DIRECTIVE('server', ARG(CF_INET|CF_FQDN, STORE(TO 'MODULE', KEY { '$SECTION' => { 'server' => '$VALUE' } }))),
    DIRECTIVE('port', ARG(CF_PORT, STORE(TO 'MODULE', KEY { '$SECTION' => {'port' => '$VALUE' } }), DEFAULT '5432')),
    DIRECTIVE('username', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$SECTION' => { 'username' => '$VALUE' } }))),
    DIRECTIVE('password', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$SECTION' => { 'password' => '$VALUE' } }))),
    DIRECTIVE('database', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$SECTION' => { 'database' => '$VALUE' } }))),
    DIRECTIVE('timeout', ARG(CF_INTEGER, STORE(TO 'MODULE', KEY { '$SECTION' => { 'timeout' => '$VALUE' } }), DEFAULT '3')),
    DIRECTIVE('retries', ARG(CF_INTEGER, STORE(TO 'MODULE', KEY { '$SECTION' => { 'retries' => '$VALUE' } }), DEFAULT '3')),
    DIRECTIVE('init_query', ARG(CF_LINE, STORE(TO 'MODULE', KEY { '$SECTION' => { 'init_query' => '$VALUE' } }))),
    DIRECTIVE('reinit_query', ARG(CF_LINE, STORE(TO 'MODULE', KEY { '$SECTION' => { 'reinit_query' => '$VALUE' } }))),
    DIRECTIVE('insert_query', ARG(CF_LINE, STORE(TO 'MODULE', KEY { '$SECTION' => { 'insert_query' => '$VALUE' } }))),
    DIRECTIVE('update_query', ARG(CF_LINE, STORE(TO 'MODULE', KEY { '$SECTION' => { 'update_query' => '$VALUE' } })))
);

##############################################################################################

sub register() {
    return $CONF_TEMPLATE;
}

sub daemonize($) {
    my $self = shift;

    # Init instance private data
    my $instdata = {
	'proctitle' => $0
    };

    $self->set_initialize_timeout($self->{'timeout'});
    $self->set_initialize_attempts($self->{'retries'});

    return $instdata;
}

sub initialize($$) {
    my ($self, $instdata) = @_;

    $self->set_reinitialize_timeout($self->{'timeout'});
    $self->set_reinitialize_attempts($self->{'retries'});
    $self->set_process_timeout($self->{'timeout'});
    $self->set_process_attempts($self->{'retries'});

    # If init_query is defined, execute it on instance startup,
    # before anything else.
    #
    # It can be used to create the table if it doesn't exist,
    # drop and recreate the table or simply empty the table
    # if it already exists
    if(defined($self->{'init_query'})) {
	# Execute the query
	my $ires = $self->db_query($self->{'init_query'}, $instdata);
	# Report error
	if(!defined($ires) || $ires->resultStatus != PGRES_COMMAND_OK || $ires->cmdTuples < 1) {
	    $self->api->logging('LOG_ERR', "Postgresql backend %s: init query failed",
					   $self->{'instance'});
	}
    }

    return $instdata;
}

sub initialize_timeout($$) {
    my ($self, $instdata) = @_;

    $self->api->logging('LOG_ERR', "Postgresql backend %s: init query timed out",
				   $self->{'instance'});

    return $instdata;
}

sub reinitialize($$) {
    my ($self, $instdata) = @_;

    $self->set_reinitialize_timeout($self->{'timeout'});
    $self->set_reinitialize_attempts($self->{'retries'});
    $self->set_process_timeout($self->{'timeout'});
    $self->set_process_attempts($self->{'retries'});

    # Destroy current connection
    # to the database server
    undef $instdata->{'conn'};

    # If reinit_query is defined, execute it on each reload,
    # before anything else.
    #
    # It can be used to create the table if it doesn't exist,
    # drop and recreate the table or simply empty the table
    # if it already exists
    if(defined($self->{'reinit_query'})) {
	# Execute the query
	my $ires = $self->db_query($self->{'reinit_query'}, $instdata);
	# Report error
	if(!defined($ires) || $ires->resultStatus != PGRES_COMMAND_OK || $ires->cmdTuples < 1) {
	    $self->api->logging('LOG_ERR', "Postgresql backend %s: reinit query failed",
					   $self->{'instance'});
	}
    }

    return $instdata;
}

sub reinitialize_timeout($$) {
    my ($self, $instdata) = @_;

    $self->api->logging('LOG_ERR', "Postgresql backend %s: reinit query timed out",
				   $self->{'instance'});

    return $instdata;
}

sub process($$$$$$$$) {
    my ($self, $instdata, $lb, $seq, $preference, $input, $ipv4, $ipv6) = @_;

    # Don't bother if no IP address is given
    return unless((defined($ipv4) && $ipv4 ne '') ||
		  (defined($ipv6) && $ipv6 ne ''));

    # Map variable names to dataset columns
    $instdata->{'params'} = {
	'lb'		=> defined($lb) ? $lb:'',
	'seq'		=> defined($seq) ? $seq:0,
	'input'		=> defined($input) ? $input:'',
	'host'		=> (defined($ipv6) && $ipv6 ne '') ?
				 $ipv6:(defined($ipv4) ? $ipv4:''),
	'ipv4'		=> defined($ipv4) ? $ipv4:'',
	'ipv6'		=> defined($ipv6) ? $ipv6:'',
	'preference'	=> defined($preference) ? $preference:0
    };

    # Update database with retrieved dataset row
    $self->update_database($instdata);
}

sub process_timeout($$) {
    my ($self, $instdata) = @_;

    $self->api->logging('LOG_WARNING', "Postgresql backend %s: database update timed out",
				       $self->{'instance'});

    # Destroy current connection
    # to the database server
    undef $instdata->{'conn'};
}

##############################################################################################

#
# Update database
#
#  This function does variable xlat within SQL string
#  and then issues the query to the database
#
#   Input:	1. object reference to backend instance
#		2. instance data hashref
#
#   Output:	1. TRUE if succeeded
#		   FALSE if failed
#
sub update_database($$) {
    my ($self, $instdata) = @_;
    my $retval = 1;
    my $errmsg;

    # Do the variable substitution
    my $pg_update_query = $self->db_xlat($self->{'update_query'}, $instdata);

    # Attempt to update the table
    my $ures = $self->db_query($pg_update_query, $instdata);

    if(!defined($ures) || $ures->resultStatus != PGRES_COMMAND_OK || $ures->cmdTuples < 1) {
	# If the update query failed, try to init the row first
	# (usually by INSERTing it into table)
	my $pg_insert_query = $self->db_xlat($self->{'insert_query'}, $instdata);

	# Attempt to insert into the table
	my $ires = $self->db_query($pg_insert_query, $instdata);

	if(!defined($ires) || $ires->resultStatus != PGRES_COMMAND_OK || $ires->cmdTuples < 1) {
	    if(defined($instdata->{'conn'})) {
		$errmsg = $instdata->{'conn'}->errorMessage;
		chop $errmsg;
	    }
	    $retval = 0;
	}

    }

    unless($retval) {
	$self->api->logging('LOG_WARNING', "Postgresql backend %s: failed to update input%s preference in database%s",
					   $self->{'instance'},
					   defined($instdata->{'param'}{'input'}) ? " ".$instdata->{'param'}{'input'}:"",
					   defined($errmsg) ? " [$errmsg]":"");
    }

    return $retval;
}
#
# Substitute variable names in SQL queries with their values
#
#   Input:	1. self object reference
#		2. sql query
#		3. instance data hashref
#
#  Output:	1. modified sql query
#
sub db_xlat($$$) {
    my ($self, $query, $instdata) = @_;

    # Do variable substitution
    $query =~ s/\$([a-zA-Z0-9\_]+)/$instdata->{'params'}{$1}/g;

    return $query;
}
#
# Issue SQL query and reconnect to database if necessary
#
#  Input:	1. object reference to backend instance
#		2. SQL query
#		3. instance data hashref
#
#  Output:	1. PG result handle,
#		   undef if failed
#
sub db_query($$$) {
    my ($self, $query, $instdata) = @_;
    my $res;

    $self->api->logging('LOG_DEBUG', $query);
    # Attempt to execute query
    $res = $self->db_execute($query, $instdata);

    # If query failed, reconnect and retry
    unless(defined($res)) {
	$self->api->logging('LOG_NOTICE', "Reconnecting to postgresql database %s",
					  $self->{'server'});
	# Reconnect to the database server
	$self->db_reconnect($instdata);
	# Retry query
	$res = $self->db_execute($query, $instdata);

	unless(defined($res)) {
	    $self->api->logging('LOG_ERR', "Postgresql database %s query failed: %s",
					   $self->{'server'},
					   $instdata->{'conn'}->errorMessage);
	    return undef;
	}
    }

    return $res;
}
#
# Execute SQL query
#
#  Input:	1. object reference to backend instance
#		2. SQL query
#		3. instance data hashref
#
#  Output:	1. PG result handle,
#		   undef if failed
#
sub db_execute($$$) {
    my ($self, $query, $instdata) = @_;

    my $pg = $instdata->{'conn'};
    return undef unless defined($pg);

    my $res = $pg->exec($query);

    return ($pg->status == PGRES_CONNECTION_OK) ? $res:undef;
}
#
# (Re)connect to backend database
#
#  Input:	1. object reference to backend instance
#		2. instance data hashref
#
#  Output:	nothing
#
sub db_reconnect($$) {
    my ($self, $instdata) = @_;

    if(defined($instdata->{'conn'})) {
	$instdata->{'conn'}->reset;
	return;
    }

    my $connectstring = sprintf("host=%s port=%u user=%s password=%s dbname=%s",
				$self->{'server'},
				$self->{'port'},
				$self->{'username'},
				$self->{'password'},
				$self->{'database'});

    # Connect to postgresql server
    my $pg = Pg::connectdb($connectstring);
    # If connected, set proc title to display connection status
    if(defined($pg) && $pg->status == PGRES_CONNECTION_OK) {
	# set proc title
	$0 = sprintf("%s [connected to %s:%s]",
		     $instdata->{'proctitle'},
		     $self->{'server'},
		     $self->{'port'});
    }
    # Save connection handle
    $instdata->{'conn'} = $pg;
}

1;
