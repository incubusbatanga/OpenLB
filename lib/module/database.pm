#
# module::database.pm
#
# Copyright (c) 2014 Marko Dinic <marko@yu.net>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.
#

package module::database;

##############################################################################################

use strict;
use warnings;

##############################################################################################

use DBI;
use Config::ContextSensitive qw(:macros);

##############################################################################################

use api::module;

##############################################################################################

our @ISA = qw(api::module);

##############################################################################################

my $CONF_TEMPLATE = SECTION(
    DIRECTIVE('type', ARG(CF_STRING, POSTPARSER(&db_check_driver), STORE(TO 'MODULE', KEY { '$SECTION' => { 'driver' => '$VALUE' } }))),
    DIRECTIVE('server', ARG(CF_INET|CF_FQDN, STORE(TO 'MODULE', KEY { '$SECTION' => { 'server' => '$VALUE' } }))),
    DIRECTIVE('port', ARG(CF_PORT, STORE(TO 'MODULE', KEY { '$SECTION' => {'port' => '$VALUE' } }))),
    DIRECTIVE('username', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$SECTION' => { 'username' => '$VALUE' } }))),
    DIRECTIVE('password', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$SECTION' => { 'password' => '$VALUE' } }))),
    DIRECTIVE('database', ARG(CF_STRING, STORE(TO 'MODULE', KEY { '$SECTION' => { 'database' => '$VALUE' } }))),
    DIRECTIVE('timeout', ARG(CF_INTEGER, STORE(TO 'MODULE', KEY { '$SECTION' => { 'timeout' => '$VALUE' } }), DEFAULT '3')),
    DIRECTIVE('retries', ARG(CF_INTEGER, STORE(TO 'MODULE', KEY { '$SECTION' => { 'retries' => '$VALUE' } }), DEFAULT '3')),
    DIRECTIVE('init_query', ARG(CF_LINE, POSTPARSER(&db_parametrize_query), STORE(TO 'MODULE', KEY { '$SECTION' => { 'queries' =>  { 'init_query' => '$VALUE' } } }))),
    DIRECTIVE('reinit_query', ARG(CF_LINE, POSTPARSER(&db_parametrize_query), STORE(TO 'MODULE', KEY { '$SECTION' => { 'queries' =>  { 'reinit_query' => '$VALUE' } } }))),
    DIRECTIVE('update_query', ARG(CF_LINE, POSTPARSER(&db_parametrize_query), STORE(TO 'MODULE', KEY { '$SECTION' => { 'queries' => { 'update_query' => '$VALUE' } } }))),
    DIRECTIVE('insert_query', ARG(CF_LINE, POSTPARSER(&db_parametrize_query), STORE(TO 'MODULE', KEY { '$SECTION' => { 'queries' =>  { 'insert_query' => '$VALUE' } } })))
);

##############################################################################################

use constant {
    DATABASE_POSTGRESQL			=> 'postgresql',
    DATABASE_MYSQL			=> 'mysql',
    DATABASE_ORACLE			=> 'oracle'
};

##############################################################################################

our %DATABASE_TYPES = (
    &DATABASE_POSTGRESQL		=> { 'module' => "Pg", 'port' => 5432, 'dsn' => "Pg:dbname=%s;host=%s;port=%d" },
    &DATABASE_MYSQL			=> { 'module' => "mysql", 'port' => 3306, 'dsn' => "mysql:database=%s;host=%s;port=%d" },
    &DATABASE_ORACLE			=> { 'module' => "Oracle", 'port' => 1512, 'dsn' => "Oracle:database=%s;host=%s;port=%d" }
);

##############################################################################################

our @DB_DRIVERS;

##############################################################################################

sub register() {
    # Get the list of available DBI drivers
    @DB_DRIVERS = DBI->available_drivers(1);
    # Return our configuration template
    return $CONF_TEMPLATE;
}

sub daemonize($) {
    my $self = shift;

    # Init instance private data
    my $instdata = {};

    $self->set_initialize_timeout($self->{'timeout'});
    $self->set_process_timeout($self->{'timeout'});

    return $instdata;
}

sub initialize($$) {
    my ($self, $instdata) = @_;

    return $self->reinitialize($instdata, 1);
}

sub reinitialize($$;$) {
    my ($self, $instdata, $init) = @_;

    # Initialize the database parameters
    $self->db_init($instdata)
	or return undef;

    # Force reconnect by closing connection to the database
    # in case parameters have changed.
    $self->cleanup($instdata);

    #
    # If init_query is defined, execute it on instance startup,
    # if reinit_query is defined, execute it on each reload,
    # both before anything else.
    #
    # They can be used to create the table if it doesn't exist,
    # drop and recreate the table or simply empty the table
    # if it already exists.
    #
    my $query_name = $init ? 'init_query':'reinit_query';
    if(defined($self->{'queries'}{$query_name}) && 
       $self->{'queries'}{$query_name} ne '') {
	# Initialize the table
	my $rows = $self->db_query($instdata, $query_name);
	if(defined($rows) && $rows > 0) {
	    $self->db_finish($instdata);
	}
    }

    return $instdata;
}

sub process($$$$$$$$) {
    my ($self, $instdata, $lb, $seq, $preference, $input, $ipv4, $ipv6) = @_;

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

    # Update database with retrieved dataset row
    $self->update_database($instdata);

    return;
}

sub process_timeout($$$$$$$$) {
    my $self = shift;

    $self->api->logging('LOG_ERR', "Database backend %s: database update timed out",
				   $self->{'instance'});

    return;
}

sub cleanup($$) {
    my ($self, $instdata) = @_;

    # Close connection if it was open
    $self->db_close($instdata);
}

##############################################################################################

#
# Update database
#
#  Input:	1. self object reference (passed implicitly)
#		2. instance private data
#
#   Output:	1. TRUE if succeeded
#		   FALSE if failed
#
sub update_database($$) {
    my ($self, $instdata) = @_;
    my $errmsg;

    # Attempt to update the table
    my $query_name = 'update_query';
    my $rows = $self->db_query($instdata, $query_name);
    if(defined($rows)) {
	# Return TRUE immediately on success
	if($rows > 0) {
	    $self->db_finish($instdata);
	    return 1;
	}

	# If the update query failed, try to init the row first
	# (usually by INSERTing it into table)
	$query_name = 'insert_query';
	$rows = $self->db_query($instdata, $query_name);
	# Return TRUE immediately on success
	if(defined($rows) && $rows > 0) {
	    $self->db_finish($instdata);
	    return 1;
	}
    }

    if(defined($instdata->{'sth'}{$query_name})) {
	$errmsg = $instdata->{'sth'}{$query_name}->errstr;
    }

    $self->api->logging('LOG_WARNING', "Database backend %s: failed to update the database%s",
				       $self->{'instance'},
				       defined($errmsg) ? " [$errmsg]":"");

    return 0;
}
#
# Initialize database parameters
#
#   Input:	1. self object reference(passed implicitly)
#		2. instance private data
#
#   Output:	1. TRUE if succeeded
#		   FALSE if failed
#
sub db_init($$) {
    my ($self, $instdata) = @_;

    my $driver = $self->{'driver'};
    return 0 unless defined($driver) &&
		    defined($DATABASE_TYPES{$driver}{'dsn'});

    # Setup correct DSN
    $instdata->{'dsn'} = sprintf($DATABASE_TYPES{$driver}{'dsn'},
				 $self->{'database'},
				 $self->{'server'},
				 defined($self->{'port'}) ?
				    $self->{'port'}:$DATABASE_TYPES{$driver}{'port'});

    $self->api->logging('LOG_DEBUG', "Database %s instance %s DSN: %s",
				     $driver,
				     $self->{'instance'},
				     $instdata->{'dsn'});

    return 1;
}
#
# (Re)connect to database
#
#   Input:	1. self object reference(passed implicitly)
#		2. instance private data
#
#   Output:	1. TRUE if succeeded
#		   FALSE if failed
#
sub db_connect($$) {
    my ($self, $instdata) = @_;

    # Attempt to connect
    my $dbh = DBI->connect('DBI:'.$instdata->{'dsn'}, $self->{'username'}, $self->{'password'});
    unless(defined($dbh)) {
	$self->api->logging('LOG_ERR', "Database %s instance %s failed to connect to database server %s", 
				       $self->{'driver'},
				       $self->{'instance'},
				       $self->{'server'});
	return 0;
    }

    $self->api->logging('LOG_INFO', "Database %s instance %s connected to server %s",
				    $self->{'driver'},
				    $self->{'instance'},
				    $self->{'server'});

    # Prepare SQL queries for later execution
    foreach my $query_name (keys %{$self->{'queries'}}) {

	# Prepare statement
	my $sth = $dbh->prepare($self->{'queries'}{$query_name});
	unless(defined($sth)) {
	    # On failure, disconnect
	    $dbh->disconnect;

	    $self->api->logging('LOG_ERR', "Database instance %s failed to prepare query \"%s\" for later execution",
					   $self->{'instance'},
					   $query_name);
	    return 0;
	}

	# Store prepared query statement handle
	$instdata->{'sth'}{$query_name} = $sth;

	$self->api->logging('LOG_DEBUG', "Database instance %s prepared query \"%s\" for later execution",
					 $self->{'instance'},
					 $query_name);
    }

    # Store database handle
    $instdata->{'dbh'} = $dbh;

    return 1;
}
#
# Close database connection and clean up
#
#   Input:	1. self object reference(passed implicitly)
#		2. instance private data
#
#   Output:	1. TRUE if succeeded
#		   FALSE if failed
#
sub db_close($$) {
    my ($self, $instdata) = @_;

    # Do nothing if database connection wasn't open
    return unless defined($instdata->{'dbh'});

    # Disconnect and destroy database connection handle
    $instdata->{'dbh'}->disconnect;
    undef $instdata->{'dbh'};
    delete $instdata->{'dbh'};
    # Destroy statement handles
    foreach my $query_name (keys %{$instdata->{'sth'}}) {
	$instdata->{'sth'}{$query_name}->finish;
	undef $instdata->{'sth'}{$query_name};
	delete $instdata->{'sth'}{$query_name};
    }
}
#
# Issue SQL query and reconnect to database if necessary
#
#   Input:	1. self object reference(passed implicitly)
#		2. instance private data
#		3. SQL query name
#
#   Output:	1. number of rows, if suceeded
#		   undef if failed
#
sub db_query($$$) {
    my ($self, $instdata, $query_name) = @_;
    my $errmsg;
    my $res;

    # Save query name
    $instdata->{'query'} = $query_name;

    $self->api->logging('LOG_DEBUG', "Database %s instance %s executing %s query: %s",
				     $self->{'driver'},
				     $self->{'instance'},
				     $query_name,
				     $self->{'queries'}{$query_name});

    # Try to execute query several times before giving up
    for(my $retries = $self->{'retries'}; $retries > 0; $retries--) {

	# Execute database query
	$res = $self->db_execute($instdata, $query_name);
	# Return immediately if we succeeded
	return $res if defined($res);

	# Otherwise, try to reconnect and retry executing the query

	$self->api->logging('LOG_NOTICE', "Reconnecting to %s database %s",
					  $self->{'driver'},
					  $self->{'server'});

	if(defined($instdata->{'sth'}{$query_name})) {
	    $errmsg = $instdata->{'sth'}{$query_name}->errstr;
	}
	# Close existing connection
	$self->db_close($instdata);
	# Now reconnect to the database
	$self->db_connect($instdata);

    }

    $self->api->logging('LOG_ERR', "Database %s server %s query %s failed%s",
				   $self->{'driver'},
				   $self->{'server'},
				   $query_name,
				   defined($errmsg) ? ": ".$errmsg:"");

    return undef;
}
#
# Execute SQL query
#
#   Input:	1. self object reference(passed implicitly)
#		2. instance private data
#		3. SQL query name
#
#   Output:	1. number of rows, if suceeded
#		   undef if failed
#
sub db_execute($$$) {
    my ($self, $instdata, $query_name) = @_;

    # This is our prepared statement handle
    my $sth = $instdata->{'sth'}{$query_name};
    # If statement handle is undefined,
    # we are probably not connected
    return undef unless defined($sth);

    # Bind values in order in which variables appear in the query

    my $i = 1;

    foreach my $param (@{$self->{'params'}{$query_name}}) {
	# Input parameters have been mapped to their
	# respective variable names by our run loop.
	# Now we can access them by simply looking
	# up parameter values by variable names in
	# the anonymous hash passed to this function.
	# Variables will be replaced with their values.
	# The rest will be used without substitution.
	my $value = ($param =~ /^\$(.+)$/) ?
			$instdata->{'params'}{$1}:$param;
	unless(defined($value)) {
	    $self->api->logging('LOG_DEBUG', "Database %s instance %s attempted to use unknown variable \$%s",
					     $self->{'driver'},
					     $self->{'instance'},
					     $param);
	    return undef;
	}

	$self->api->logging('LOG_DEBUG', "Database %s instance %s query %s parameter %d: \$%s = %s",
					 $self->{'driver'},
					 $self->{'instance'},
					 $query_name,
					 $i,
					 $param,
					 $value);
	# Bind parameter value
	$sth->bind_param($i++, $value);
    }

    # Execute query with defined timeout
    my $res = $sth->execute();
    unless($res) {
	# Something's wrong with the database connection,
	# try to reconnect and re-execute the query
	$self->api->logging('LOG_ERR', "Database %s instance %s failed to execute() query",
				       $self->{'driver'},
				       $self->{'instance'});
	return undef;
    }

    # If query was a SELECT, return the number
    # of retrieved rows. If query was an INSERT
    # or an UPDATE, return the number of rows
    # affected.
    return (defined($sth->{'NUM_OF_FIELDS'}) &&
	    $sth->{'NUM_OF_FIELDS'} > 0) ?
	    $sth->rows:($res > 0 ? $res:0);
}
#
# Fetch SQL query results
#
#   Input:	1. self object reference(passed implicitly)
#		2. instance private data
#
#   Output:	1. a single result row as an array
#		   undef if failed
#
sub db_fetch($$) {
    my ($self, $instdata) = @_;

    my $query_name = $instdata->{'query'};
    return undef unless defined($query_name);

    my $sth = $instdata->{'sth'}{$query_name};
    return undef unless defined($sth);

    my $rows = $sth->rows;

    $self->api->logging('LOG_DEBUG', "Database %s instance %s query returns %d row%s", $rows == 1 ? "":"s",
				     $self->{'driver'},
				     $self->{'instance'},
				     $rows);
    last unless($rows > 0);

    # Get results
    $sth->fetch();
}
#
# Clean up SQL query results
#
#   Input:	1. self object reference(passed implicitly)
#		2. instance private data
#
#   Output:	nothing
#
sub db_finish($$) {
    my ($self, $instdata) = @_;

    my $query_name = $instdata->{'query'};
    return undef unless defined($query_name);

    my $sth = $instdata->{'sth'}{$query_name};
    if(defined($sth)) {
	# End query results processing
	$sth->finish();
    }
}

##############################################################################################
#         C O N F I G   A R G U M E N T   P O S T P A R S E R   F U N C T I O N S            #
##############################################################################################

#
# Check if the required DBI driver is installed on the system.
#
sub db_check_driver($$$$$$$) {
    my ($conf, $dir, $value, $store, $map, $section, $nested_section) = @_;

    unless(defined($value)) {
	return (0, "database backend requires database type to be specified");
    }

    my $driver = $DATABASE_TYPES{$value}{'module'};
    unless(defined($driver)) {
	return (0, "database type \"".$value."\" is not supported");
    }

    unless(scalar(grep(/$driver/, @DB_DRIVERS))) {
	return (0, "no DBI module installed for database type \"".$value."\"");
    }

    return 1;
}
#
# Parametrize regular SQL query.
#
sub db_parametrize_query($$$$$$$) {
    my ($conf, $dir, $value, $store, $map, $section, $nested_section) = @_;

    # Create list of query parameters by extracting
    # variable names and storing them in exact order
    # in which they appear in the query
    my @params = ($value =~ /(\"[^\"]*\"|\'[^\']*\'|\$[a-zA-Z\_]+|[^a-zA-Z0-9\_]+(?=::))/g);
    # Strip quotes
    for(my $i = 0; $i < scalar(@params); $i++) {
	$params[$i] =~ s/(^[\"\']|[\"\']$)//g;
    }
    # Replace variable names with placeholders '?',
    # thereby parametrizing the query string
    $value =~ s/(\"[^\"]*\"|\'[^\']*\'|\$[a-zA-Z\_]+|[^a-zA-Z0-9\_]+(?=::))/?/g;
    # Prior to executing the query, parameters (values
    # of given variables) will be bound to the prepared
    # statement in the same order in which they are
    # listed here
    $store->{'MODULE'}{$section}{'params'}{$dir} = \@params;

    return (1, $value);
}

1;
