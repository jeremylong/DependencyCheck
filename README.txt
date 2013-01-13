About:
DependencyCheck is a utility that attempts to detect publically disclosed
vulnerabilities contained within project dependencies. It does this by determining
if there is a Common Platform Enumeration (CPE) identifier for a given dependency.
If found, it will generate a report linking to the associated CVE entries.

Usage:
$ mvn package
$ cd target
$ java -jar DependencyCheck-0.2.5.2.jar -h
$ java -jar DependencyCheck-0.2.5.2.jar -a Testing -out . -scan ./test-classes/org.mortbay.jetty.jar -scan ./test-classes/struts2-core-2.1.2.jar -scan ./lib

Then load the resulting 'DependencyCheck-Report.html' into your favorite browser.

Author: Jeremy Long (jeremy.long@gmail.com)

Copyright (c) 2012 Jeremy Long. All Rights Reserved.