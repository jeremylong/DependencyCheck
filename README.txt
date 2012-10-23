About:
DependencyCheck is a utility that attempts to detect publically disclosed
vulnerabilities contained within project dependencies. It does this by determining
if there is a Common Platform Enumeration (CPE) identifier for a given dependency. 
If found, it will generate a report linking to the associated CVE entries. 

Usage:
$ mvn package
$ cd target
$ java -jar DependencyCheck-0.2.0.jar -h
$ java -jar DependencyCheck-0.2.0.jar -a Testing -out . -scan ./test-classes/org.mortbay.jetty.jar -scan ./test-classes/struts2-core-2.1.2.jar -scan ./lib

Then load the resulting 'Testing.html' into your favorite browser.

Important note - DependencyCheck should be run to analyze a project at least once every week. 
The reason for this is that it downloads data from the National Vulnerability Database hosted 
by NIST. If more then a week goes by without DependencyCheck updating the data, a full update
can take an 90 minutes or more (a lot of data needs to be downloaded and processed).

Author: Jeremy Long (jeremy.long@gmail.com)

Copyright (c) 2012 Jeremy Long. All Rights Reserved.
