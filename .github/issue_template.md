Please delete any un-needed section from the following issue template:

### Reporting Bugs/Errors
When reporting errors, 99% of the time log file output is required. Please post the log file as a [gist](https://gist.github.com/) and provide a link in the new issue.

### Reporting False Positives
When reporting a false positive please include:
- The location of the dependency (Maven GAV, URL to download the dependency, etc.)
- The CPE that is believed to be false positive
  - Please report the CPE not the CVE

#### Example
False positive on library foo.jar - reported as cpe:/a:apache:tomcat:7.0
```xml
<dependency>
   <groupId>org.sample</groupId>
   <artifactId>foo</artifactId>
   <version>1.0</version>
</dependency>
```