Caching ODC's H2 Database
=========================================

Many users of dependency-check ensure that ODC runs as fast as possible by caching
the entire `data` directory included the H2 database (`odc.mv.db`). The location of the `data`
directory is different for each integration (cli, maven, gradle, etc.), however each
allows users to configure this location.

Within the `data` directory there is a `cache` directory that contains temporary caches
of data requested that is not stored in the database and is generally build specific
- but can be re-used.

There are two primary strategies used:

1. Single node database updater with multiple node "readers" 

Use a single node to build the database using the integration in update only mode
(e.g., `--updateOnly` for the cli) and specify the data directory location (see 
the configuration documentation for each integration's configuration).

The `data` directory is then archived somewhere accessible to all nodes.
Subsequent nodes that perform scanning will download the archived database before 
scanning. These "reader" nodes would be configured with `--noupdate` (or the related 
configuration to disable the updates in each integration) so they are not reliant
on outgoing calls.

The cached `data` directory (and H2 database) is generally updated by the single 
node/process daily in this use case - but could be designed with a more frequent update.

2. Multiple node database updaters collaborating on a common cache location

Some users have a slightly modified version of the above caching strategy. Instead
of only having a single update node - they allow all nodes to update. However,
the entire `data` directory is zipped and stored in a common location, including the H2
database, `cache`, and in some cases cached data from multiple upstream sources.

Each node will execute a scan (with updates enabled) and if successful the updated
`data` directory is zipped and uploaded to the common location for use by other nodes.
This has the small advantage of being updated faster and will store the cache between 
executions which can improve the performance on some builds, with the disadvantage of
needing to allow all nodes to update the common cache, and thus requiring some degree of
consistency in how they configure ODC.

Additional Notes
----------------

The `data` directory may also contain cached data from other upstream sources, dependent 
on which analyzers are enabled. Ensuring that file modification times are retained during 
archiving and un-archiving will make these safe to cache, which is especially important in
a multi-node update strategy.
