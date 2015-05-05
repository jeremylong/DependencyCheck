Using a Database Server
=======================
<font color="red">**WARNING: This discusses an advanced setup and you may run into issues.**</font>

Out of the box dependency-check uses a local H2 database. The location of the database
file is configured using the data directory configuration option (see
[CLI](https://jeremylong.github.io/DependencyCheck/dependency-check-cli/arguments.html)).

Some organizations may want to use a more robust centralized database. Currently, [H2 in
server mode](http://www.h2database.com/html/tutorial.html#using_server) and
[MySQL](https://www.mysql.com/) have been tested. In general, the setup is done by creating
a central database, setting up a single instance of dependency-check, which can connect to the
Internet, that is run in update-only mode once a day. Then the other dependency-check clients
can connect, using a read-only connection, to perform the analysis. Please note that if the
clients are unable to access the Internet the analysis may result in a few false negatives;
see the note about Central [here](./index.html).

To setup a centralized database the following generalized steps can be used:

<ol><li>Create the database and tables using either <a href="https://github.com/jeremylong/DependencyCheck/blob/master/dependency-check-core/src/main/resources/data/initialize.sql">initialize.sql</a>
   or <a href="https://github.com/jeremylong/DependencyCheck/blob/master/dependency-check-core/src/main/resources/data/initialize_mysql.sql">initialize_mysql.sql</a>.</li>
<li>The account that the clients will connect using must have select granted on the tables.
     <ul><li>Note, if the clients performing the scans should run with the noupdate setting. A single
       instance of the dependency-check client should be setup with update enabled and the account
       used during the update process will need to be granted update rights on the tables.
     </li></ul>
</li><li>Dependency-check clients running scans will need to be configured to use the central database:
   <ul><li>The database driver will need to be specified using the dbDriver and if the driver is not
         already in the classpath the dbDriverPath options will need to be set (see the specific configuration
         options for Maven, Ant, CLI, and Jenkins).</li>
       <li>The connection string, database user name, and the database user's password will also need to be configured.</li>
   </ul>
</li></ol>
Depending on the database being used, you may need to customize the [dbStatements.properties](https://github.com/jeremylong/DependencyCheck/blob/master/dependency-check-core/src/main/resources/data/dbStatements.properties).

As always, feel free to open an [issue](https://github.com/jeremylong/DependencyCheck/issues)
or post a question to the [dependency-check google group](https://groups.google.com/forum/#!forum/dependency-check).
