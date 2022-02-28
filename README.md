[![Maven Central](https://img.shields.io/maven-central/v/org.owasp/dependency-check-maven.svg)](https://mvnrepository.com/artifact/org.owasp/dependency-check-maven) ![Build and Deploy](https://github.com/jeremylong/DependencyCheck/workflows/Build%20and%20Deploy/badge.svg?branch=main) [![Coverity Scan Build Status](https://img.shields.io/coverity/scan/1654.svg)](https://scan.coverity.com/projects/dependencycheck) [![Codacy Badge](https://api.codacy.com/project/badge/Grade/6b6021d481dc41a888c5da0d9ecf9494)](https://www.codacy.com/app/jeremylong/DependencyCheck?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=jeremylong/DependencyCheck&amp;utm_campaign=Badge_Grade) [![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/843/badge)](https://bestpractices.coreinfrastructure.org/projects/843) [![Apache 2.0 License](https://img.shields.io/badge/license-Apache%202-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0.txt)

[![Black Hat Arsenal](https://raw.githubusercontent.com/toolswatch/badges/master/arsenal/usa/2018.svg?sanitize=true)](http://www.toolswatch.org/2018/05/black-hat-arsenal-usa-2018-the-w0w-lineup/) [![Black Hat Arsenal](https://www.toolswatch.org/badges/arsenal/2015.svg)](https://www.toolswatch.org/2015/06/black-hat-arsenal-usa-2015-speakers-lineup/) [![Black Hat Arsenal](https://www.toolswatch.org/badges/arsenal/2014.svg)](https://www.toolswatch.org/2014/06/black-hat-usa-2014-arsenal-tools-speaker-list/) [![Black Hat Arsenal](https://www.toolswatch.org/badges/arsenal/2013.svg)](https://www.toolswatch.org/2013/06/announcement-blackhat-arsenal-usa-2013-selected-tools/)

Dependency-Check
================

Dependency-Check is a Software Composition Analysis (SCA) tool that attempts to detect publicly disclosed vulnerabilities contained within a project's dependencies. It does this by determining if there is a Common Platform Enumeration (CPE) identifier for a given dependency. If found, it will generate a report linking to the associated CVE entries.

Documentation and links to production binary releases can be found on the [github pages](http://jeremylong.github.io/DependencyCheck/). Additionally, more information about the architecture and ways to extend dependency-check can be found on the [wiki].

7.0.0 Upgrade Notice
--------------
If upgrading to 7.0.0 or higher, there were breaking changes. If you get an error indicating you can't connect
to the database you will need to run the purge command to remove the old database:
- gradle: `./gradlew dependencyCheckPurge`
- maven: `mvn org.owasp:dependency-check-maven:7.0.0:purge`
- cli: `dependency-check.sh --purge`

Homebrew users upgrading to dependency-check 7.0.0 will need to purge their old database.

Current Releases
-------------
### Jenkins Plugin

For instructions on the use of the Jenkins plugin please see the [OWASP Dependency-Check Plugin page](https://wiki.jenkins-ci.org/display/JENKINS/OWASP+Dependency-Check+Plugin).

### Command Line

More detailed instructions can be found on the
[dependency-check github pages](http://jeremylong.github.io/DependencyCheck/dependency-check-cli/).
The latest CLI can be downloaded from github in the [releases section](https://github.com/jeremylong/DependencyCheck/releases).

On *nix
```
$ ./bin/dependency-check.sh -h
$ ./bin/dependency-check.sh --out . --scan [path to jar files to be scanned]
```
On Windows
```
> .\bin\dependency-check.bat -h
> .\bin\dependency-check.bat --out . --scan [path to jar files to be scanned]
```
On Mac with [Homebrew](http://brew.sh)
Note - homebrew users upgrading from 5.x to 6.0.0 will need to run `dependency-check.sh --purge`.
```
$ brew update && brew install dependency-check
$ dependency-check -h
$ dependency-check --out . --scan [path to jar files to be scanned]
```

### Maven Plugin

More detailed instructions can be found on the [dependency-check-maven github pages](http://jeremylong.github.io/DependencyCheck/dependency-check-maven).
By default, the plugin is tied to the `verify` phase (i.e. `mvn verify`). Alternatively,
one can directly invoke the plugin via `mvn org.owasp:dependency-check-maven:check`.

The dependency-check plugin can be configured using the following:

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

Development Prerequisites
-------------

For installation to pass, you must have the following components installed:
* Java: `java -version` 1.8
* Maven: `mvn -version` 3.5.0 and higher

Tests cases require:
* dotnet core version 6.0
* Go: `go version` 1.12 and higher
* Ruby [bundler-audit](https://github.com/rubysec/bundler-audit#install)
* [Yarn](https://classic.yarnpkg.com/en/docs/install/)
* [pnpm](https://pnpm.io/installation)

Development Usage
-------------
The following instructions outline how to compile and use the current snapshot. While every intention is to maintain a stable snapshot it is recommended
that the release versions listed above be used.

The repository has some large files due to test resources. The team has tried to clean up the history as much as possible.
However, it is recommended that you perform a shallow clone to save yourself time:

```bash
git clone --depth 1 https://github.com/jeremylong/DependencyCheck.git
```

On *nix
```
$ mvn -s settings.xml install
$ ./cli/target/release/bin/dependency-check.sh -h
$ ./cli/target/release/bin/dependency-check.sh --out . --scan ./src/test/resources
```
On Windows
```
> mvn -s settings.xml install
> .\cli\target\release\bin\dependency-check.bat -h
> .\cli\target\release\bin\dependency-check.bat --out . --scan ./src/test/resources
```

Then load the resulting 'dependency-check-report.html' into your favorite browser.

### Docker

In the following example it is assumed that the source to be checked is in the current working directory and the reports will be written to `$(pwd)/odc-reports`. Persistent data and cache directories are used, allowing you to destroy the container after running.

For Linux:
```sh
#!/bin/sh

DC_VERSION="latest"
DC_DIRECTORY=$HOME/OWASP-Dependency-Check
DC_PROJECT="dependency-check scan: $(pwd)"
DATA_DIRECTORY="$DC_DIRECTORY/data"
CACHE_DIRECTORY="$DC_DIRECTORY/data/cache"

if [ ! -d "$DATA_DIRECTORY" ]; then
    echo "Initially creating persistent directory: $DATA_DIRECTORY"
    mkdir -p "$DATA_DIRECTORY"
fi
if [ ! -d "$CACHE_DIRECTORY" ]; then
    echo "Initially creating persistent directory: $CACHE_DIRECTORY"
    mkdir -p "$CACHE_DIRECTORY"
fi

# Make sure we are using the latest version
docker pull owasp/dependency-check:$DC_VERSION

docker run --rm \
    -e user=$USER \
    -u $(id -u ${USER}):$(id -g ${USER}) \
    --volume $(pwd):/src:z \
    --volume "$DATA_DIRECTORY":/usr/share/dependency-check/data:z \
    --volume $(pwd)/odc-reports:/report:z \
    owasp/dependency-check:$DC_VERSION \
    --scan /src \
    --format "ALL" \
    --project "$DC_PROJECT" \
    --out /report
    # Use suppression like this: (where /src == $pwd)
    # --suppression "/src/security/dependency-check-suppression.xml"
```

For Windows:
```bat
@echo off

set DC_VERSION="latest"
set DC_DIRECTORY=%USERPROFILE%\OWASP-Dependency-Check
SET DC_PROJECT="dependency-check scan: %CD%"
set DATA_DIRECTORY="%DC_DIRECTORY%\data"
set CACHE_DIRECTORY="%DC_DIRECTORY%\data\cache"

IF NOT EXIST %DATA_DIRECTORY% (
    echo Initially creating persistent directory: %DATA_DIRECTORY%
    mkdir %DATA_DIRECTORY%
)
IF NOT EXIST %CACHE_DIRECTORY% (
    echo Initially creating persistent directory: %CACHE_DIRECTORY%
    mkdir %CACHE_DIRECTORY%
)

rem Make sure we are using the latest version
docker pull owasp/dependency-check:%DC_VERSION%

docker run --rm ^
    --volume %CD%:/src ^
    --volume %DATA_DIRECTORY%:/usr/share/dependency-check/data ^
    --volume %CD%/odc-reports:/report ^
    owasp/dependency-check:%DC_VERSION% ^
    --scan /src ^
    --format "ALL" ^
    --project "%DC_PROJECT%" ^
    --out /report
    rem Use suppression like this: (where /src == %CD%)
    rem --suppression "/src/security/dependency-check-suppression.xml"
```

Building From Source
-------------
To build dependency-check (using Java 8) run the command:

```
mvn -s settings.xml install
```

Building the documentation
--------------------------

The documentation on the [github pages](http://jeremylong.github.io/DependencyCheck/) is generated from this repository:

    mvn -s settings.xml site  site:staging

Once done, point your browser to `./target/staging/index.html`.

Building The Docker Image
-------------
To build dependency-check docker image run the command:

```
mvn -s settings.xml install
./build-docker.sh
```

License
-------

Permission to modify and redistribute is granted under the terms of the Apache 2.0 license. See the [LICENSE.txt](https://raw.githubusercontent.com/jeremylong/DependencyCheck/master/LICENSE.txt) file for the full license.

Dependency-Check makes use of several other open source libraries. Please see the [NOTICE.txt][notices] file for more information.

Copyright (c) 2012-2022 Jeremy Long. All Rights Reserved.

  [wiki]: https://github.com/jeremylong/DependencyCheck/wiki
  [notices]: https://github.com/jeremylong/DependencyCheck/blob/master/NOTICE.txt
