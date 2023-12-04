Caching ODC's H2 Database
=========================================

Many users of dependency-check ensure that ODC runs as fast as possible by caching
the `data` directory (or in some cases just the H2 database). Where the `data`
directory exists is different for each integration (cli, maven, gradle, etc.).
However, each integration allows users to configure the location of the data directory.

Within the data directory there is a cache directory that contains temporary caches
of data requested that is not stored in the database and is generally build specific
- but can be re-used. There are two primary stratigies used:

1. Cache the H2 database

Use a single node to build the database using the integration in update only mode
(e.g., `--updateOnly` for the cli) and specify the data directory location (see 
the configuration documentation for each integrgations configuration). The data
directory is then archived. Subsequent nodes that perform scanning will then
download the archived database and configure the scan to occur and in general,
the node would be configured with `--noupdate` (or the releated configuration to
disable the updates in each configuration). The database is generally updated daily
in this use case - but could be designed with a more frequent update.

2. Cache the H2 database and the cache

Some users have a slightly modified version of the above caching strategy. Instead
of only having a single update node - they allow all nodes to update. However,
the data directory is zipped and stored in an common location. Each node will execute
a scan (with updates enabled) and if succesful the updated data directory is zipped
and uploaded to the common location. This has the small advantage of being updated
faster and will store the cache between executions which can improve the performance
on some builds.
