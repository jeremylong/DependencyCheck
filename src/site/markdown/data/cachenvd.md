Snapshotting the NVD
====================

The [Mirroring the NVD from NIST](./mirrornvd.html) topic describes briefly
how to use the [Nist-Data-Mirror](https://github.com/stevespringett/nist-data-mirror/)
project to cache the NVD locally and run Dependency Check (D-C) against the
local cache.

This topic goes into a bit more depth with the [cli](../dependency-check-cli/index.html)
client, focusing on the following use case.

1. You wish to have daily local snapshots of the NVD, so that
2. in order to compare later runs of D-C with earlier runs, you can compare
   "apples with apples".

In other words: It is sometimes desirable to run a comparison D-C analysis
against the same NVD snapshot that an earlier D-C report used.

In the steps below, concrete examples will be given assuming an Ubuntu Linux
system. Hopefully, enough explanation is provided that the steps can easily be
translated to other systems.

Build Nist-Data-Mirror
----------------------

1. Perform a "git clone" of [Nist-Data-Mirror](https://github.com/stevespringett/nist-data-mirror/)
2. Follow the build and run [instructions](https://github.com/stevespringett/nist-data-mirror/blob/master/README.md#user-content-building).
   You will be left with a build artifact called `nist-data-mirror.jar`.

Set Up a Daily NVD Download Job
-------------------------------

On Linux, the way to do this using the [cron daemon](http://linux.die.net/man/8/cron).
"Cron jobs" are configured by invoking [crontab](http://linux.die.net/man/5/crontab).
For example, invoke `crontab -e` to add a line like the following to your
crontab file:

    4 5 * * * ~/.local/bin/nvd_download.sh ~/NVD ~/.local/jars

This would run a job on your system at 4:05 AM daily to run the
[nvd_download.sh](general/nvd_download.sh) shell script with the two given
arguments. The script is simple:

```sh
#!/bin/sh
NVD_ROOT=$1/`date -I`
JAR_PATH=$2/nist-data-mirror-1.0.0.jar
java -jar $JAR_PATH $NVD_ROOT
rm $NVD_ROOT/*.xml # D-C works directly with .gz files anyway.
```

Nist-Data-Mirror will automatically create the directory, download the
.xml.gz files, and extract the .xml files alongside them. Given the parameters
in the cron example above, the new directory will be `~/NVD/2015-08-03` if
executed on August 3<sup>rd</sup>, 2015. The download for 2015-08-03 pulled 47
MiB, and took up a total of 668 MiB after extracting from the compressed
archive format. It turns out that D-C works directly with the .xml.gz files,
so the above script preserves disk space by deleting the .xml files.

Invoke the Command-Line Using a Specific Daily Snapshot
-------------------------------------------------------

An example script named [dep-check-date.sh](general/dep-check-date.sh) is
shown below, which facilitates a D-C scan against an arbitrary NVD snapshot:

```sh
#!/bin/sh
CLI_LOCATION=~/.local/dependency-check-1.2.11
CLI_SCRIPT=$CLI_LOCATION/bin/dependency-check.sh
NVD_PATH=$1/`date -I -d $2`
NVD=file://$NVD_PATH
shift 2 # We've used the first two params. The rest go to CLI_SCRIPT.
$CLI_SCRIPT --cveUrl20Base $NVD/nvdcve-2.0-%d.xml.gz \
    --cveUrl12Base $NVD/nvdcve-%d.xml.gz \
    --cveUrl20Modified $NVD/nvdcve-2.0-Modified.xml.gz \
    --cveUrl12Modified $NVD/nvdcve-Modified.xml.gz \
    --data $NVD_PATH $@
```

The script takes advantage of the `date` command's ability to parse a variety
of date formats. The following invocation would successfully point to the
`~/NVD/2015-08-03` folder.

    $ ./dep-check-date.sh ~/NVD "08/03/2015" -app Foo -scan /path/to/Foo --out ~/DCreports/FooFollowup/

If today happened to be August 4th, 2015, `"yesterday"` also would have
worked. Also notice the usage of the `--data` parameter. This places the H2
database file directly in the folder alongside the .xml.gz files. This is
critical, so that D-C doesn't run against another version of the database,
like the usual default in `$CLI_LOCATION/data`.