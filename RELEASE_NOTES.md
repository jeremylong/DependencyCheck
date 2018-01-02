# Release Notes

Please see the [dependency-check google group](https://groups.google.com/forum/#!forum/dependency-check) for the release notes on versions not listed below.

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