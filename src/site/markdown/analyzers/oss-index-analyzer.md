OSS Index Analyzer
================

Uses the [OSS Index](https://ossindex.sonatype.org/) APIs to report on
vulnerabilities not found in the NVD. The collection of identified Package-URL
identifiers are submitted to the OSS Index for analysis and the resulting
identified vulnerabilities are included in the report. In addition, vulnerabilities
found in both the NVD and OSS Index may have additional references added.

This analyzer requires an Internet connection.
