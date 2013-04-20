DependencyCheck
=========

DependencyCheck is a utility that attempts to detect publically disclosed vulnerabilities contained within project dependencies. It does this by determining if there is a Common Platform Enumeration (CPE) identifier for a given dependency. If found, it will generate a report linking to the associated CVE entries.

More information can be found on the [wiki].

Usage
-

> $ mvn package

> $ cd target

> $ java -jar dependency-check-[version].jar -h

> $ java -jar dependency-check-[version].jar -a Testing -out . -scan ./test-classes -scan ./lib

Then load the resulting 'DependencyCheck-Report.html' into your favorite browser.

Mailing List
-

Subscribe: [dependency-check+subscribe@googlegroups.com] [subscribe]

Post: [dependency-check@googlegroups.com] [post]

Copyright & License
-

Dependency-Check is Copyright (c) 2012-2013 Jeremy Long. All Rights Reserved.

Permission to modify and redistribute is granted under the terms of the GPLv3 license. See the [LICENSE.txt] [GPLv3] file for the full license.

Dependency-Check makes use of several other open source libraries. Please see the [NOTICE.txt] [notices] file for more information.


  [wiki]: https://github.com/jeremylong/DependencyCheck/wiki
  [subscribe]: mailto:dependency-check+subscribe@googlegroups.com
  [post]: mailto:dependency-check@googlegroups.com
  [GPLv3]: https://github.com/jeremylong/DependencyCheck/blob/master/LICENSE.txt
  [notices]: https://github.com/jeremylong/DependencyCheck/blob/master/NOTICES.txt