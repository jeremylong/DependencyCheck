[![Build Status](https://travis-ci.org/jeremylong/DependencyCheck.svg?branch=master)](https://travis-ci.org/jeremylong/DependencyCheck) [![Coverity Scan Build Status](https://scan.coverity.com/projects/1654/badge.svg)](https://scan.coverity.com/projects/dependencycheck) [![Codacy Badge](https://api.codacy.com/project/badge/Grade/6b6021d481dc41a888c5da0d9ecf9494)](https://www.codacy.com/app/jeremylong/DependencyCheck?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=jeremylong/DependencyCheck&amp;utm_campaign=Badge_Grade) [![Apache 2.0 License](https://img.shields.io/badge/license-Apache%202-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0.txt)

[![Black Hat Arsenal](https://www.toolswatch.org/badges/arsenal/2015.svg)](https://www.toolswatch.org/2015/06/black-hat-arsenal-usa-2015-speakers-lineup/) [![Black Hat Arsenal](https://www.toolswatch.org/badges/arsenal/2014.svg)](https://www.toolswatch.org/2014/06/black-hat-usa-2014-arsenal-tools-speaker-list/) [![Black Hat Arsenal](https://www.toolswatch.org/badges/arsenal/2013.svg)](https://www.toolswatch.org/2013/06/announcement-blackhat-arsenal-usa-2013-selected-tools/)

Dependency-Check
================

Dependency-Check is a utility that attempts to detect publicly disclosed vulnerabilities contained within project dependencies. It does this by determining if there is a Common Platform Enumeration (CPE) identifier for a given dependency. If found, it will generate a report linking to the associated CVE entries.

Documentation and links to production binary releases can be found on the [github pages](http://jeremylong.github.io/DependencyCheck/). Additionally, more information about the architecture and ways to extend dependency-check can be found on the [wiki].

Current Releases
-------------
### Jenkins Plugin

For instructions on the use of the Jenkins plugin please see the [OWASP Dependency-Check Plugin page](https://wiki.jenkins-ci.org/display/JENKINS/OWASP+Dependency-Check+Plugin).

### Command Line

More detailed instructions can be found on the
[dependency-check github pages](http://jeremylong.github.io/DependencyCheck/dependency-check-cli/).
The latest CLI can be downloaded from bintray's
[dependency-check page](https://bintray.com/jeremy-long/owasp/dependency-check).

On *nix
```
$ ./bin/dependency-check.sh -h
$ ./bin/dependency-check.sh --project Testing --out . --scan [path to jar files to be scanned]
```
On Windows
```
> bin/dependency-check.bat -h
> bin/dependency-check.bat --project Testing --out . --scan [path to jar files to be scanned]
```
On Mac with [Homebrew](http://brew.sh)
```
$ brew update && brew install dependency-check
$ dependency-check -h
$ dependency-check --project Testing --out . --scan [path to jar files to be scanned]
```

### Maven Plugin

More detailed instructions can be found on the [dependency-check-maven github pages](http://jeremylong.github.io/DependencyCheck/dependency-check-maven).
The plugin can be configured using the following:

```xml
<project>
    <build>
        <plugins>
            ...
            <plugin>
              <groupId>org.owasp</groupId>
              <artifactId>dependency-check-maven</artifactId>
              <executions>
                  <execution>
                      <goals>
                          <goal>check</goal>
                      </goals>
                  </execution>
              </executions>
            </plugin>
            ...
        </plugins>
        ...
    </build>
    ...
</project>
```

### Ant Task

For instructions on the use of the Ant Task, please see the [dependency-check-ant github page](http://jeremylong.github.io/DependencyCheck/dependency-check-ant).

Development Usage
-------------
The following instructions outline how to compile and use the current snapshot. While every intention is to maintain a stable snapshot it is recommended
that the release versions listed above be used.

The repository has some large files due to test resources. The team has tried to cleanup the history as much as possible.
However, it is recommended that you perform a shallow clone to save yourself time:

```bash
git clone --depth 1 git@github.com:jeremylong/DependencyCheck.git
```

On *nix
```
$ mvn install
$ ./dependency-check-cli/target/release/bin/dependency-check.sh -h
$ ./dependency-check-cli/target/release/bin/dependency-check.sh --project Testing --out . --scan ./src/test/resources
```
On Windows
```
> mvn install
> dependency-check-cli/target/release/bin/dependency-check.bat -h
> dependency-check-cli/target/release/bin/dependency-check.bat --project Testing --out . --scan ./src/test/resources
```

Then load the resulting 'DependencyCheck-Report.html' into your favorite browser.

### Docker

In the following example it is assumed that the source to be checked is in the actual directory. A persistent data directory and a persistent report directory is used so that the container can be destroyed after running it to make sure that you use the newest version, always.
```
# After the first run, feel free to change the owner of the directories to the owner of the created files and the permissions to 744
DATA_DIRECTORY=$HOME/OWASP-Dependency-Check/data
REPORT_DIRECTORY=/$HOME/OWASP-Dependency-Check/reports

if [ ! -d $DATA_DIRECTORY ]; then
	echo "Initially creating persistent directories"
        mkdir -p $DATA_DIRECTORY
        chmod -R 777 $DATA_DIRECTORY
    
        mkdir -p $REPORT_DIRECTORY
        chmod -R 777 $REPORT_DIRECTORY
fi

docker pull owasp/dependency-check # Make sure it is the actual version

docker run --rm \
        --volume $(pwd):/src \
        --volume $DATA_DIRECTORY:/usr/share/dependency-check/data \
        --volume $REPORT_DIRECTORY:/report \
        --name dependency-check \
        dc \
        --suppression "/src/security/dependency-check-suppression.xml"\
        --format "ALL" \
        --project "My OWASP Dependency Check Project" \
```


Mailing List
------------

Subscribe: [dependency-check+subscribe@googlegroups.com] [subscribe]

Post: [dependency-check@googlegroups.com] [post]

Archive: [google group](https://groups.google.com/forum/#!forum/dependency-check)

Copyright & License
-

Dependency-Check is Copyright (c) 2012-2016 Jeremy Long. All Rights Reserved.

Permission to modify and redistribute is granted under the terms of the Apache 2.0 license. See the [LICENSE.txt](https://raw.githubusercontent.com/jeremylong/DependencyCheck/master/LICENSE.txt) file for the full license.

Dependency-Check makes use of several other open source libraries. Please see the [NOTICE.txt][notices] file for more information.


  [wiki]: https://github.com/jeremylong/DependencyCheck/wiki
  [subscribe]: mailto:dependency-check+subscribe@googlegroups.com
  [post]: mailto:dependency-check@googlegroups.com
  [notices]: https://github.com/jeremylong/DependencyCheck/blob/master/NOTICE.txt
