[![Maven Central](https://img.shields.io/maven-central/v/org.owasp/dependency-check-maven.svg)](https://mvnrepository.com/artifact/org.owasp/dependency-check-maven) [![Build Status](https://travis-ci.org/jeremylong/DependencyCheck.svg?branch=master)](https://travis-ci.org/jeremylong/DependencyCheck) [![Coverity Scan Build Status](https://scan.coverity.com/projects/1654/badge.svg)](https://scan.coverity.com/projects/dependencycheck) [![Codacy Badge](https://api.codacy.com/project/badge/Grade/6b6021d481dc41a888c5da0d9ecf9494)](https://www.codacy.com/app/jeremylong/DependencyCheck?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=jeremylong/DependencyCheck&amp;utm_campaign=Badge_Grade) [![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/843/badge)](https://bestpractices.coreinfrastructure.org/projects/843) [![Apache 2.0 License](https://img.shields.io/badge/license-Apache%202-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0.txt)

[![Black Hat Arsenal](https://www.toolswatch.org/badges/arsenal/2015.svg)](https://www.toolswatch.org/2015/06/black-hat-arsenal-usa-2015-speakers-lineup/) [![Black Hat Arsenal](https://www.toolswatch.org/badges/arsenal/2014.svg)](https://www.toolswatch.org/2014/06/black-hat-usa-2014-arsenal-tools-speaker-list/) [![Black Hat Arsenal](https://www.toolswatch.org/badges/arsenal/2013.svg)](https://www.toolswatch.org/2013/06/announcement-blackhat-arsenal-usa-2013-selected-tools/)

Dependency-Check
================

Dependency-Check is a Software Composition Analysis (SCA) tool that attempts to detect publicly disclosed vulnerabilities contained within a project's dependencies. It does this by determining if there is a Common Platform Enumeration (CPE) identifier for a given dependency. If found, it will generate a report linking to the associated CVE entries.

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
> .\bin\dependency-check.bat -h
> .\bin\dependency-check.bat --project Testing --out . --scan [path to jar files to be scanned]
```
On Mac with [Homebrew](http://brew.sh)
```
$ brew update && brew install dependency-check
$ dependency-check -h
$ dependency-check --project Testing --out . --scan [path to jar files to be scanned]
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
$ mvn install
$ ./cli/target/release/bin/dependency-check.sh -h
$ ./cli/target/release/bin/dependency-check.sh --project Testing --out . --scan ./src/test/resources
```
On Windows
```
> mvn install
> .\dependency-check-cli\target\release\bin\dependency-check.bat -h
> .\dependency-check-cli\target\release\bin\dependency-check.bat --project Testing --out . --scan ./src/test/resources
```

Then load the resulting 'dependency-check-report.html' into your favorite browser.

### Docker

In the following example it is assumed that the source to be checked is in the current working directory. Persistent data and report directories are used, allowing you to destroy the container after running.

```
#!/bin/sh

OWASPDC_DIRECTORY=$HOME/OWASP-Dependency-Check
DATA_DIRECTORY="$OWASPDC_DIRECTORY/data"
REPORT_DIRECTORY="$OWASPDC_DIRECTORY/reports"

if [ ! -d "$DATA_DIRECTORY" ]; then
    echo "Initially creating persistent directories"
    mkdir -p "$DATA_DIRECTORY"
    chmod -R 777 "$DATA_DIRECTORY"

    mkdir -p "$REPORT_DIRECTORY"
    chmod -R 777 "$REPORT_DIRECTORY"
fi

# Make sure we are using the latest version
docker pull owasp/dependency-check

docker run --rm \
    --volume $(pwd):/src \
    --volume "$DATA_DIRECTORY":/usr/share/dependency-check/data \
    --volume "$REPORT_DIRECTORY":/report \
    owasp/dependency-check \
    --scan /src \
    --format "ALL" \
    --project "My OWASP Dependency Check Project" \
    --out /report
    # Use suppression like this: (/src == $pwd)
    # --suppression "/src/security/dependency-check-suppression.xml"

```


Upgrade Notes
-------------

### Upgrading from **1.x.x** to **2.x.x**

Note that when upgrading from version 1.x.x that the following changes will need to be made to your configuration.

#### Suppression file

In order to support multiple suppression files, the mechanism for configuring suppression files has changed.
As such, users that have defined a suppression file in their configuration will need to update.

See the examples below:

##### Ant

Old:

```xml
<dependency-check
  failBuildOnCVSS="3"
  suppressionFile="suppression.xml">
</dependency-check>
```

New:

```xml
<dependency-check
  failBuildOnCVSS="3">
  <suppressionFile path="suppression.xml" />
</dependency-check>
```

##### Maven

Old:

```xml
<plugin>
  <groupId>org.owasp</groupId>
  <artifactId>dependency-check-maven</artifactId>
  <configuration>
    <suppressionFile>suppression.xml</suppressionFile>
  </configuration>
</plugin>
```

New:

```xml
<plugin>
  <groupId>org.owasp</groupId>
  <artifactId>dependency-check-maven</artifactId>
  <configuration>
    <suppressionFiles>
      <suppressionFile>suppression.xml</suppressionFile>
    </suppressionFiles>
  </configuration>
</plugin>
```

### Gradle

In addition to the changes to the suppression file, the task `dependencyCheck` has been
renamed to `dependencyCheckAnalyze`.

Old:

```groovy
buildscript {
    repositories {
		mavenLocal()
    }
    dependencies {
        classpath 'org.owasp:dependency-check-gradle:2.0.1-SNAPSHOT'
    }
}
apply plugin: 'org.owasp.dependencycheck'

dependencyCheck {
	suppressionFile='path/to/suppression.xml'
}
check.dependsOn dependencyCheckAnalyze
```

New:
```groovy
buildscript {
    repositories {
		mavenLocal()
    }
    dependencies {
        classpath 'org.owasp:dependency-check-gradle:2.0.1-SNAPSHOT'
    }
}
apply plugin: 'org.owasp.dependencycheck'

dependencyCheck {
	suppressionFiles = ['path/to/suppression1.xml', 'path/to/suppression2.xml']
}
check.dependsOn dependencyCheckAnalyze
```

Mailing List
------------

Subscribe: [dependency-check+subscribe@googlegroups.com] [subscribe]

Post: [dependency-check@googlegroups.com] [post]

Archive: [google group](https://groups.google.com/forum/#!forum/dependency-check)

Copyright & License
-

Dependency-Check is Copyright (c) 2012-2017 Jeremy Long. All Rights Reserved.

Permission to modify and redistribute is granted under the terms of the Apache 2.0 license. See the [LICENSE.txt](https://raw.githubusercontent.com/jeremylong/DependencyCheck/master/LICENSE.txt) file for the full license.

Dependency-Check makes use of several other open source libraries. Please see the [NOTICE.txt][notices] file for more information.


  [wiki]: https://github.com/jeremylong/DependencyCheck/wiki
  [subscribe]: mailto:dependency-check+subscribe@googlegroups.com
  [post]: mailto:dependency-check@googlegroups.com
  [notices]: https://github.com/jeremylong/DependencyCheck/blob/master/NOTICE.txt
