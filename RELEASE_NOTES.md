# Release Notes

## [Version 6.5.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.5.1) (2021-12-17)

### Changes

 - Updated the dependency-check-maven plugin to correctly support SNAPSHOT version when a classifier is specified (#3787).
 - Improved the analysis of Swift package manager (package.resolved - see #3813).
 - General code maintenance and false positive reductions.
 - See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/37?closed=1).

## [Version 6.5.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.5.0) (2021-11-08)

### Changes

 - Updated build configuration to create [reproducible builds](https://reproducible-builds.org/).
 - Updated automated release process to work with branch protection.
 - Resolved several false positives in the Java ecosystem.
 - Enabled the Swift Resolved analyzer per #3735
 - Improved iOS support per #3168 and #3765
 - Added the a new pnpm Analyzer
 - Fixed issue with some npm and yarn analysis failing due to large audit output
 - See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/36?closed=1).

## [Version 6.4.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.4.1) (2021-10-11)

### Changes

- Added download attempts with increasing wait time for `CVE meta` files from the NVD to prevent rate limiting issues (see [#3725](https://github.com/jeremylong/DependencyCheck/pull/3725)).
- See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/35?closed=1).

## [Version 6.4.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.4.0) (2021-10-11)

### Changes

- Increased timeout between downloads from the NVD to prevent rate limiting issues (see [#3722](https://github.com/jeremylong/DependencyCheck/pull/3722)).
  - `cveStartYear` is now configurable and can be set to any year from 2002 to present.
  - `cveWaitTime` is a new configuration option to define how many milliseconds to wait between NVD downloads; default is 4000 ms (see [#3690](https://github.com/jeremylong/DependencyCheck/pull/3690)).
  - The NVD CVE data files are now being cached for up to 4 hours in case a download fails, re-running ODC will use the cached version.
- Fixed NPE in the ODC maven plugin (see [#3702](https://github.com/jeremylong/DependencyCheck/pull/3702).
- See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/34?closed=1).

## [Version 6.3.2](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.3.2) (2021-09-29)

### Changes

- Reduced chance of rate limiting when download files from NVD (see [#2670](https://github.com/jeremylong/DependencyCheck/pull/3670)).
- Fixed bug causing some transitive dependencies being skipped in the odc-maven-plugin (see [#3627](https://github.com/jeremylong/DependencyCheck/pull/3627)).
- See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/33?closed=1).

## [Version 6.3.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.3.1) (2021-09-01)

### Changes

- Fixed [ConcurrentModificationException](https://github.com/jeremylong/DependencyCheck/issues/3618)
- See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/32?closed=1).

## [Version 6.3.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.3.0) (2021-08-31)

### Changes

- Many updates were made to improve performance on large scans, reduce false positives, and other bug fixes.
- Increased the width of four columns in the database; if you use a an external database you should also update the width (see [upgrade_5.1.sql](https://github.com/jeremylong/DependencyCheck/blob/main/core/src/main/resources/data/upgrade_5.1.sql)).
- See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/31?closed=1).

## [Version 6.2.2](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.2.2) (2021-06-10)

### Changes

- Resolved issue with database connections introduced in 6.2.0 (see https://github.com/jeremylong/DependencyCheck/issues/3432).
- See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/30?closed=1).

## [Version 6.2.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.2.1) (2021-06-08)

### Changes

- Resolved issue with database connections introduced in 6.2.0 (see https://github.com/jeremylong/DependencyCheck/issues/3416).
- See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/29?closed=1).

## [Version 6.2.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.2.0) (2021-05-29)

### Changes

- Added an experimental Perl CPAN analyzer [#3378](https://github.com/jeremylong/DependencyCheck/pull/3378)
  - Note that the full DSL of the CPAN is not yet supported so any required dependency is analyzed (i.e. there is no way to exclude development requirements)
- Improved database performance [#3206](https://github.com/jeremylong/DependencyCheck/pull/3206)
- The archive analyzer now extracts files from RPM archives [#3226](https://github.com/jeremylong/DependencyCheck/pull/3226)
- Ensure ordered output in reports [#3243](https://github.com/jeremylong/DependencyCheck/pull/3343)
- Several minor bug fixes and updates to reduce false positives
- See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/27?closed=1).

## [Version 6.1.6](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.1.6) (2021-04-29)

### Changes

- Resolved issue with Sarif report (#3243)
- Resolved issue with Ruby Bundle Audit (#3256)
- Several minor bug fixes and updates to reduce false positives
- See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/26?closed=1).

## [Version 6.1.5](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.1.5) (2021-03-31)

### Changes

- Fixed a second NPE introduced in 6.1.3 (see #3246)
- See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/25?closed=1).

## [Version 6.1.4](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.1.4) (2021-03-30)

### Changes

- Fixed an NPE introduced in 6.1.3 (see #3212)
- See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/24?closed=1).

## [Version 6.1.3](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.1.3) (2021-03-22)

### Changes

- Modified the new CPE matching strategy to be more performant (#3207)
- Upgraded a vulnerable dependency (velocity-engine-core/CVE-2020-13936) (#3205)
- See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/23?closed=1).

## [Version 6.1.2](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.1.2) (2021-03-08)

### Changes

- Fixed a bug in the Sarif report generation.
- Fixed a bug with the Ant task not being able to read the dependency-check properties file in 6.1.1.
- Added a new CPE matching strategy to reduce false negatives.
- CLI and Ant task will no longer be published to bintray.
- Several minor bug fixes.
- See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/22?closed=1).

## [Version 6.1.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.1.1) (2021-02-13)

### Changes

- Added missing configuration options for yarn and msbuild.
- Several bug fixes.
- See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/21?closed=1).

## [Version 6.1.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.1.0) (2021-01-27)

### Changes

- Added SARIF file format per [#3081](https://github.com/jeremylong/DependencyCheck/issues/3081).
- Added support for Yarn per [#3063](https://github.com/jeremylong/DependencyCheck/pull/3063).
- False positive reduction and minor bug fixes.
- See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/20?closed=1).

## [Version 6.0.5](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.0.5) (2021-01-07)

### Changes

- Added missing command line arguments per #3028 and #3035.
- False positive reduction and minor bug fixes.
- See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/19?closed=1).

## [Version 6.0.4](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.0.4) (2020-12-31)

### Changes

- Minor bug fixes and reduction of false positives.
- See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/18?closed=1).

## [Version 6.0.3](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.0.3) (2020-11-03)

### Changes

- Added a bash command completion script (see #2916); to add completion to your shell
  `completion-for-dependency-check.sh` can be found in the bin directory of the CLI:
   ```bash
   $ source completion-for-dependency-check.sh
   ```
- An experimental PIP File Analyzer was added (see #2877).
- Analysis of Node JS produced several false positives (see #2796); the analysis has
  been updated to reduce the number of false positives.
  - If analyzing Node JS projects it is highly recommended to disable the Node JS Analyzer
    and solely rely on the Node Audit Analyzer. There are plans to rework Node JS analysis
    in a future release.
- Support for external Oracle databases has been add for the 6.x releases (see #2899)
- Resolved several reported false positives.
- Several other bug fixes have been implemented; see the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/17?closed=1).

## [Version 6.0.2](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.0.2) (2020-09-27)

### Changes

- The project is migrating from hosting the release archives on Bintray and moving them to Github under the assets for each [release](https://github.com/jeremylong/DependencyCheck/releases)
  - **Please update any automation you have to point to the new location.**
- Npm Audit Analyzer now correctly skips dev dependencies (`--nodeAuditSkipDevDependencies`); see #2482.
- GoLang Analyzer now scans transitive dependencies; see #2680.
- Several bug fixes found in 6.0.1.

- Full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/16?closed=1).

## [Version 6.0.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.0.1) (2020-09-13)

### Changes

- Improved error messages when upgrading from 5.x to 6.x; due to breaking database changes if the old
  database schema is detected an error message is produced indicating that the old database should be purged.
- Fixed the database path for the Ant and Gradle plugins.
- Added locking around the RetireJS updates to resolve read/write conflicts in CI environments.

- Full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/15?closed=1).

## [Version 6.0.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.0.0) (2020-09-07)

### Changes

- Updated database schema; this is a *breaking change* and anyone using an external database or those whom
  specify the data directory will need recreate the database (including users of the docker image). The schema
  changes were made to:
  - Improve the CVSS data, when available, per #2547
  - Improve the way that ecosystems are determined
  - Improve the update performance of external databases
- Users with an **external Oracle** database will not be able to upgrade as https://github.com/jeremylong/DependencyCheck/issues/2755
  has not been resolved - as such, version 6.0.0 does not support Oracle.
- Users mirroring the NVD - ODC 6.0.0 requires the use of the version 1.1 data feeds
  - please ensure you are using 1.1 not the 1.0 data feed.
  
- Full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/14?closed=1).

## [Version 5.3.2](https://github.com/jeremylong/DependencyCheck/releases/tag/v5.3.2) (2020-03-26)

### Changes

- Several bug fixes
- Full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/13?closed=1).

## [Version 5.3.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v5.3.1) (2020-03-10)

### Changes

- Added an experimental PE Analyzer that reads the PE headers of DLL and EXE files; see [#2448](https://github.com/jeremylong/DependencyCheck/pull/2448) and [#2446](https://github.com/jeremylong/DependencyCheck/pull/2446).
- Lots of bug fixes and updates to false positives and false negatives
  - You may see a large one time performance hit when updating the database after updating to 5.3.1
- Full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/12?closed=1).

## [Version 5.3.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v5.3.0) (2020-01-15)

### Changes

- Updated the JSON report to include a new field for unscored vulnerabilities (see #2392).
- Updated the XML report to include a new attribute to flag unscored vulnerabilities (see #2392)
  - see https://github.com/jeremylong/DependencyCheck/blob/master/core/src/main/resources/schema/dependency-check.2.3.xsd
- Added an experimental analyzer that will lookup Node libraries in the NVD data feeds (see #1249)
  - `NpmCPEAnalyzer`, experimental analyzers must be enabled, controlled via property `analyzer.npm.cpe.enabled` which will be exposed as a configuration option in the next release.
- Full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/11?closed=1).

## [Version 5.2.4](https://github.com/jeremylong/DependencyCheck/releases/tag/v5.2.4) (2019-11-12)

### Changes

- Reverted a in 5.2.3 that caused the dependency-check.sh script to fail on some systems (including the docker image).
- Fixed issue with pretty printing the XML report.
- Full listing of [resolved issues](https://github.com/jeremylong/DependencyCheck/issues?utf8=%E2%9C%93&q=is%3Aissue++is%3Aclosed+milestone%3A5.2.4).

## [Version 5.2.3](https://github.com/jeremylong/DependencyCheck/releases/tag/v5.2.3) (2019-11-11)

### Changes

- Updated to use the NVD JSON 1.1 schema (see [#2273](https://github.com/jeremylong/DependencyCheck/issues/2273)).
  - This update is 100% backward compatible with the 1.0 schema if you are mirroring the 1.0 JSON files.
- Added `nonProxyHosts` to the CLI and gradle plugin.
- False positive corrections.
- General code cleanup/bug fix.
- Full listing of [resolved issues](https://github.com/jeremylong/DependencyCheck/issues?utf8=%E2%9C%93&q=is%3Aissue++is%3Aclosed+milestone%3A5.2.3) and [pull requests](https://github.com/jeremylong/DependencyCheck/pulls?utf8=%E2%9C%93&q=is%3Apr+milestone%3A5.2.3+is%3Aclosed+).

## [Version 5.2.2](https://github.com/jeremylong/DependencyCheck/releases/tag/v5.2.2) (2019-09-22)

### Changes

- False positive corrections
- General code cleanup/bug fix
- Full listing of [resolved issues](https://github.com/jeremylong/DependencyCheck/issues?utf8=%E2%9C%93&q=is%3Aissue++is%3Aclosed+milestone%3A5.2.2).

## [Version 5.2.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v5.2.1) (2019-08-04)

### Changes

- Updated docker container to include additional database drivers and reduce overall image size
- Performance improvements when using some external databases
- False positive corrections
- General code cleanup/bug fix
- Full listing of [resolved issues](https://github.com/jeremylong/DependencyCheck/issues?utf8=%E2%9C%93&q=is%3Aissue++is%3Aclosed+milestone%3A5.2.1).

## [Version 5.2.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v5.2.0) (2019-07-21)

### Changes

- Resolved formatting issues within the CSV report
- False positive corrections
- Renamed three properties within the `dependencycheck.properties`; there is no impact unless you are using a properties file in your build to control the CLI.
- Added support for rbenv for Bundle Audit Analysis (see https://github.com/jeremylong/DependencyCheck/issues/2060).
- Full listing of [resolved issues](https://github.com/jeremylong/DependencyCheck/issues?utf8=%E2%9C%93&q=is%3Aissue++is%3Aclosed+milestone%3A5.2.0).

## [Version 5.1.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v5.1.1) (2019-07-15)

### Changes

- False positive corrections
- General code cleanup
- Full listing of [resolved issues](https://github.com/jeremylong/DependencyCheck/issues?q=is%3Aissue+milestone%3A5.1.1+is%3Aclosed).

## [Version 5.1.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v5.1.0) (2019-06-28)

### Changes

- Added two experimental analyzers to support Golang.
- Updated the suppression schema to support suppressing OSS Index, RetireJS, NSP vulnerabilities, etc.
  - The HTML report now uses the 1.3 suppression schema by default to generate suppression rules.
  - See the updated examples on https://jeremylong.github.io/DependencyCheck/general/suppression.html.
- Added optional configuration to add credentials to the OSS Index analysis.
- Resolved issues when Oracle or MySQL were used as a centralized database in 5.0.0.
- Full listing of [resolved issues](https://github.com/jeremylong/DependencyCheck/issues?utf8=%E2%9C%93&q=is%3Aissue+is%3Aopen+milestone%3A5.1.0) and [pull requests](https://github.com/jeremylong/DependencyCheck/pulls?utf8=%E2%9C%93&q=is%3Apr+milestone%3A5.1.0).

## [Version 5.0.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v5.0.0) (2019-06-09)

### Changes

- Add caching of OSS-Index, Central Analyzer, and Node Audit analysis results.
- General bug fixes identified in the previous milestone releases; see [5.0.0 resolved issues](https://github.com/jeremylong/DependencyCheck/issues?utf8=%E2%9C%93&q=is%3Aissue+is%3Aopen+milestone%3A5.0.0+) and [pull requests](https://github.com/jeremylong/DependencyCheck/pulls?utf8=%E2%9C%93&q=is%3Apr+milestone%3A5.0.0).

## [Version 5.0.0-M3](https://github.com/jeremylong/DependencyCheck/releases/tag/v5.0.0-M3) (2019-05-06)

### Breaking Changes

- OWASP dependency-check now uses the [NVD Meta files](https://nvd.nist.gov/vuln/data-feeds#JSON_FEED) in addition to the `*.json.gz` files. If you have a local mirror of the NVD you must now mirror the meta data files. The [nist-data-mirror](https://github.com/stevespringett/nist-data-mirror) has been updated to include these files.

### Changes

- Several bug fixes and minor enhancements have been made; see the related [issues](https://github.com/jeremylong/DependencyCheck/issues?utf8=%E2%9C%93&q=+milestone%3A5.0.0-M3+) and [pull requests](https://github.com/jeremylong/DependencyCheck/pulls?utf8=%E2%9C%93&q=+milestone%3A5.0.0-M3+).
- Multiple report formats can be specified; if you wanted just two of the reports you no longer need to use ALL.
- A new JUNIT formatted report has been added; this provides a different way to integrate with Jenkins builds; the following example creates a JUNIT report with failures for any CVE with a CVSS score greater than or equal to 7.0 the Jenkins pipeline script shows how to publish the report:
  **`pom.xml`**
  ```xml
  <plugin>
    <groupId>org.owasp</groupId>
    <artifactId>dependency-check-maven</artifactId>
    <version>5.0.0-M3</version>
    <configuration>
      <formats>
          <format>HTML</format>
          <format>JUNIT</format>
      </formats>
      <junitFailOnCVSS>7.0</junitFailOnCVSS>
    </configuration>
    <executions>
      <execution>
        <goals>
          <goal>verify</goal>
        </goals>
      </execution>
    </executions>
  </plugin>
  ```
  **`Jenkinsfile`**
  ```groovy
  stage ('Build') {
    steps {
      sh 'mvn verify'
    }
    post {
      success {
        junit 'target/dependency-check-junit.xml'
      }
    }
  }
  ```

## [Version 5.0.0-M2](https://github.com/jeremylong/DependencyCheck/releases/tag/v5.0.0-M2) (2019-03-11)

### Breaking Changes

- [dotnet core](https://dotnet.microsoft.com/download/dotnet-core/2.2) must be installed to analyze .NET assemblies.
- The retire.js analyzer is no longer considered experimental and is enabled by default.

## [Version 5.0.0-M1](https://github.com/jeremylong/DependencyCheck/releases/tag/v5.0.0-M1) (2019-02-17)

### Breaking Changes

- All previously deprecated arguments to the plugins and CLI have been removed.
- The NVD CVE data import now uses the JSON data feeds instead of the XML data feeds.
  - The parameter names have changed if you are mirroring the data feeds locally.
- For developers using the core engine the identifiers have been drastically changed;
  ODC now uses [Package URL](https://github.com/package-url/packageurl-java) for software
  identifiers and CPE objects from [CPE-Parser](https://github.com/stevespringett/CPE-Parser)
  for vulnerable library identifiers.
- All of the report formats have been updated to include the additional data from the NVD CVE JSON data feeds.

### Changes

- Major re-working of the dependency to CPE matching algorithm.
- Introduced ecosystem filtering - this is an internal process that tries to ensure vulnerabilities
  from one technology stack do not appear on a dependency built using a completely different stack (e.g.
  NodeJS vulnerabilities should not show up on a .NET DLL).

## [Version 4.0.2](https://github.com/jeremylong/DependencyCheck/releases/tag/v4.0.2) (2019-01-01)

### Enhancements

- Added the ability for the dependency-check-maven plugin to scan the `dependencyManagement` section
  of the `pom.xml`. Note that in the default configuration the dependency management section is skipped.
  To enable this feature set `<skipDependencyManagement>false</skipDependencyManagement>`.
- If using a local Nexus server (v2 or v3 pro) it is now possible to provide authentication credentials.
  - Previous versions only worked with anonymous/unauthenticated access.
  - See [issue #977](https://github.com/jeremylong/DependencyCheck/issues/977)

### Bug Fixes

- Updated fix for transitive dependencies with known vulnerabilities (guava and commons-collections)
  so that the upgrade occurs correctly in other integrations that utilize core; see
  [issue #1562](https://github.com/jeremylong/DependencyCheck/issues/1561#issuecomment-450112110).
- Resolved several false positives

## [Version 4.0.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v4.0.1) (2018-12-17)

### Bug Fixes

- Fixed issue with false positives due to Lucene upgrade. See [#1531](https://github.com/jeremylong/DependencyCheck/issues/1580).
- Resolved several false positives.
- Resolved typo in documentation.

## [Version 4.0.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v4.0.0) (2018-11-21)

### Breaking Changes

- OWASP dependency-check no longer supports running in JRE/JDK 7; JRE/JDK 8 or higher is required run dependency-check. See [#1531](https://github.com/jeremylong/DependencyCheck/issues/1531).

### Bug Fixes

- Upgraded dependencies to resolve published vulnerabilities (Guava and Lucene); See [#1561](https://github.com/jeremylong/DependencyCheck/issues/1561).

## [Version 3.3.4](https://github.com/jeremylong/DependencyCheck/releases/tag/v3.3.4) (2018-10-28)

### Bug Fixes

- Resolved bug with parsing license information during analysis of Node.js modules.

## [Version 3.3.3](https://github.com/jeremylong/DependencyCheck/releases/tag/v3.3.3) (2018-10-27)

### Enhancements

- Migrated the NSP Analyzer to use the Node Audit APIs instead; see [#1366](https://github.com/jeremylong/DependencyCheck/issues/1366).
  - Note that the analyzer and configuration was changed to NodeAuditAnalyzer.
  - Configurations for the NSP analyzer have been deprecated and will control the NodeAuditAnalyzer if used; note that the NSP configuration options will be removed in a future release.
- The [dependency-check-gradle](https://github.com/jeremylong/dependency-check-gradle) plugin was updated to include a default scan set
  of ['src/main/resources','src/main/webapp'] and any dependencies contained in these directories will be analyzed. The purpose of this
  enhancement is to enable the RetireJS Analyzer to scan JavaScript files that may be included.

### Bug Fixes

- Resolved **false negative** on Bouncy Castle JAR files; see [#1500](https://github.com/jeremylong/DependencyCheck/issues/1500).
- Resolved **false negatives** that may occur when using the Maven plugin if transitive dependencies of a library in use and is also declared as a primary dependency in a scope that is not used; see [#1512](https://github.com/jeremylong/DependencyCheck/issues/1512).
- Resolved **false negatives** on libraries that contain an update version or timestamp tacked onto the end of the version number; see [#1537](https://github.com/jeremylong/DependencyCheck/issues/1537).
  - The resolution for these false negatives may generate some false positives, please continue to report false positives and the engine can continue to be tuned.
- Fixed bug preventing multiple proxies from being defined for Maven; see [#831](https://github.com/jeremylong/DependencyCheck/issues/831).
- Updated the suppress buttons in the HTML report to generate the XML using the latest suppression schema; see [#489](https://github.com/jeremylong/DependencyCheck/issues/1489).
- Added the `--artifactoryUrl` argument to the CLI - this was missed when the Artifactory Analyzer was previously added; see [#1492](https://github.com/jeremylong/DependencyCheck/issues/1492).
- Updated test cases so that they no longer fail behind a proxy; see [#1493](https://github.com/jeremylong/DependencyCheck/issues/1493).
- Resolved several reported false positives; see [#1504](https://github.com/jeremylong/DependencyCheck/issues/1504), [#1513](https://github.com/jeremylong/DependencyCheck/issues/1513),
  [#1515](https://github.com/jeremylong/DependencyCheck/issues/1515), [#1529](https://github.com/jeremylong/DependencyCheck/issues/1529), [#1535](https://github.com/jeremylong/DependencyCheck/issues/1535),
  and [#1437](https://github.com/jeremylong/DependencyCheck/issues/1437).
- Fixed copy/paste error in JavaDoc; see [#1509](https://github.com/jeremylong/DependencyCheck/issues/1509).

## [Version 3.3.2](https://github.com/jeremylong/DependencyCheck/releases/tag/v3.3.2) (2018-09-14)

### Bug Fixes

- Gradle plugin was updated to include backward compatability with gradle < v4.0; see [#95](https://github.com/jeremylong/dependency-check-gradle/issues/95).
- Gradle plugin improved handling of Android project; see [#94](https://github.com/jeremylong/dependency-check-gradle/issues/94)
- CLI used an incorrect key for RetireJS causing the analyzer to not be loaded in some cases; see [#1440](https://github.com/jeremylong/DependencyCheck/issues/1440).
- Resolved failure in the `CentralAnalyzer` when the pom.xml is not available in Central; see [#1439](https://github.com/jeremylong/DependencyCheck/issues/1439).
- Resolved exception when JAR files contain invalid pom.xml files outside of META-INF; see [#1438](https://github.com/jeremylong/DependencyCheck/issues/1438).
- Resolved several reported false positives.

## [Version 3.3.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v3.3.1) (2018-08-06)

### Bug Fixes

- Fixed error handling with regard to invalid manifest files contained within JAR files; see [#1024](https://github.com/jeremylong/DependencyCheck/issues/1024).
- Fixed parsing of pom.xml files, in some cases a SAX Exception would be thrown; see [#1400](https://github.com/jeremylong/DependencyCheck/issues/1400).
- Fixed bug that caused dependency-check to crash if the temporary directory and data directory were on different drives; see [#1394](https://github.com/jeremylong/DependencyCheck/issues/1394).
- Fixed bug in dependency-check-maven where an aggregate analysis did not scan all files defined in the ScanSet; see [#1421](https://github.com/jeremylong/DependencyCheck/issues/1421).
- Fixed NPE in dependency-check-gradle that occurred when artifacts where included using `implementation files("./lib/some.jar")`; see [#91](https://github.com/jeremylong/dependency-check-gradle/issues/91).

### Enhancements

- An Nuget Packages.config Analyzer was added; see [#1412](https://github.com/jeremylong/DependencyCheck/issues/1412).

## [Version 3.3.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v3.3.0) (2018-07-22)

### Bug Fixes

- The dependency-check-gradle plugin can now analyze multi-project android builds. See [PR #09](https://github.com/jeremylong/dependency-check-gradle/pull/90) for more information.
- In some cases extremely large project may cause dependency-check to fail due to the analysis time. Previously, the analysis was capped at 10 minutes; the timeout was increased to 20 minutes and made configurable if this continues to be an issue for some users. See [issue #936](https://github.com/jeremylong/DependencyCheck/issues/936) for more information.
- Some pom.xml files could not be analyzed because they contained a doctype definition. The parser has been enhanced to strip the doctype definitions.
- Fixed issue where, in some cases, temporary files were not correctly cleaned up in Jenkins and gradle builds.
- Fixed issue where, in some cases, files were retrieved from Maven Central using HTTP instead of HTTPS. See [issue #1325](https://github.com/jeremylong/DependencyCheck/issues/1325) for more information.
  - Additionally, a retry count was added when attempting to download pom.xml files during analysis.
- Fixed issue where nodejs dependencies were not correctly analyzed. See [issue #1355](https://github.com/jeremylong/DependencyCheck/issues/1355) for more information.
- Fixed issue where the CWE was not written to the CSV report.
- In addition, general bug fixes, code cleanup, and false positive/negatives updates were made.

### Enhancements

- An Artifactory Analyzer was added that can be used to in-place of the Central Analyzer for organizations that use Artifactory.
  - Note, for maven and gradle builds the Artifactory analyzer will not improve the analysis. The information gained by using the Central, Artifactory, or Nexus Analyzers is already obtained from the build system.
- An experimental Retire JS analyzer has been added to analyze client side JavaScript.
  - This utilizes information from the RetireJS repo on github. If you have a proxy that prevents access you will either need to have access granted to https://raw.githubusercontent.com/Retirejs/retire.js/master/repository/jsrepository.json or host the file internally, update the environment variable `analyzer.retirejs.repo.js.ur`, and periodically update the file.
  - This analyzer is considered experimental, but the team expects this to be promoted quickly.
- NuGet dependencies contained in MSBuild files are now included in the scan. See [Issue #1131](https://github.com/jeremylong/DependencyCheck/issues/1131) for more details.
- Cocoapod's Podfile.lock is now analyzed when present. See [PR #1324](https://github.com/jeremylong/DependencyCheck/pull/1324) for more information.

## [Version 3.2.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v3.2.1) (2018-05-28)

### Bug Fixes

- In some cases when using the Maven or Gradle plugins the GAV coordinates were not being added as an Identifier causing suppression rules to fail; this has been resolved (#1298)
- Documentation Update (SCM links in the maven site were broken) (#1297)
- False positive reduction (#1290)
- Enhanced logging output for TLS failures to better assist with debugging (#1269)
- Resolved a Null Pointer Exception (#1296)

## [Version 3.2.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v3.2.0) (2018-05-21)

### Security Fix

- Unsafe unzip operations ([zip slip](https://github.com/snyk/zip-slip-vulnerability)), as reported by the Snyk Security Research Team, have been corrected. CVE-2018-12036 allows attackers to write to arbitrary files via a crafted archive that holds directory traversal filenames.

### Bug Fixes

- The dependency-check-maven plugin no longer uses the [Central Analyzer](https://jeremylong.github.io/DependencyCheck/analyzers/central-analyzer.html) by default
- Updated dependency-check-maven so that it will not fail when your multi-module build has dependencies that have not yet been built in the reactor (See [#740](https://github.com/jeremylong/DependencyCheck/issues/740))
  - Note if the required dependency has not yet been built in the reactor and the dependency is available in a configured repository dependency-check-maven, as expected, would pull the dependency from the repository for analysis.
- Minor documentation updates
- False positive reduction
- Fixed the Gradle Plugin and Ant Task so that the temp directory is properly cleaned up after execution
- Removed TLSv1 from the list of protocols used by default (See [#1237](https://github.com/jeremylong/DependencyCheck/pull/1237))

### Enhancements

- Excess white space has been removed from the XML and HTML reports; the JSON report is still pretty printed (a future release will convert this to a configurable option)
- Better error reporting
- Changed to use commons-text instead of commons-lang3 as a portion of commons-lang3 was moved to commonts-text
- Added more flexible suppression rules with the introduction of the `until` attribute (see [#1145](https://github.com/jeremylong/DependencyCheck/issues/1145) and [dependency-suppression.1.2.xsd](https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.2.xsd)

## [Version 3.1.2](https://github.com/jeremylong/DependencyCheck/releases/tag/v3.1.2) (2018-04-02)

### Bug fixes

- Updated the NVD URLs
- Updated documentation
- Add project references to the JSON and XML report; in aggregate scans using Maven or Gradle the dependencies
  will include a reference to the project/module where they were found
- The configuration option `versionCheckEnabled` was added to Maven to allow users to disable the check for
  new versions of dependency-check; this will be added to gradle plugin, Ant Task, and the CLI in a future release
- The XML and JSON reports were fixed so that the correct version number is displayed see [issue #1109](https://github.com/jeremylong/DependencyCheck/issues/1109)
- The initial database creation time for H2 databases was improved
- Changes made to decrease false positive and false negatives

## [Version 3.1.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v3.1.1) (2018-01-29)

### Bug fixes

- Fixed the Central Analyzer to use the updated SHA1 query syntax.
- Reverted change that broke Maven 3.1.0 compatability; Maven 3.1.0 and beyond is once again supported.
- False positive reduction.
- Minor documentation cleanup.

## [Version 3.1.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v3.1.0) (2018-01-02)

### Enhancements

- Major enhancements to the Node and NSP analyzer - the analyzers are now considered
  production ready and should be used in combination.
- Added a shutdown hook so that if the update process is interrupted while using an H2
  database the lock files will be properly removed allowing future executions of ODC to
  succeed.
- UNC paths can now be scanned using the CLI.
- Batch updates are now used which may help with the update speed when using some DBMS
  instead of the embedded H2.
- Upgrade Lucene to 5.5.5, the highest version that will allow us to maintain Java 7 support

### Bug fixes

- Fixed the CSV report output to correctly list all fields.
- Invalid suppression files will now break the build instead of causing ODC to
  skip the usage of the suppression analyzer.
- Fixed bug in Lucene query where LARGE entries in the pom.xml or manifest caused
  the query to break.
- General cleanup, false positive, and false negative reduction.

## [Version 3.0.2](https://github.com/jeremylong/DependencyCheck/releases/tag/v3.0.2) (2017-11-13)

### Bug fixes

- Updated the query format for the CentralAnalyzer; the old format caused the CentralAnalyzer to fail

## [Version 3.0.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v3.0.1) (2017-10-20)

### Bug fixes

- Fixed a database connection issue that affected some usages.

## [Version 3.0.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v3.0.0) (2017-10-16)

- Several bug fixes and false positive reduction
  - The 2.x branch introduced several new false positives – but also reduced the false negatives
- Java 9 compatibility update
- Stability issues with the Central Analyzer resolved
  - This comes at a cost of a longer analysis time
- The CSV report now includes the GAV and CPE
- The Hint Analyzer now supports regular expressions
- If show summary is disabled and vulnerable libraries are found that fail the build details are no longer displayed in the console – only that vulnerable libraries were identified
- Resolved issues with threading and multiple connections to the embedded H2 database
  - This allows the Jenkins pipeline, Maven Plugin, etc. to safely run parallel executions of dependency-check
