/*
 * This file is part of dependency-check-maven.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */

import java.nio.charset.Charset;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;

String oldReport = FileUtils.readFileToString(new File(basedir, "old/target/dependency-check-report.xml"), Charset.defaultCharset().name());
int count = StringUtils.countMatches(oldReport, "pkg:maven/org.owasp.test.aggregate.issue-1527/war@1.0.0-SNAPSHOT");
if (count == 0) {
    System.out.println(String.format("war-1.0.0-SNAPSHOT was not identified"));
    return false;
}
count = StringUtils.countMatches(oldReport, "pkg:maven/org.apache.james/apache-mime4j-core@0.7.2");
if (count == 0) {
    System.out.println("org.apache.james:apache-mime4j-core:0.7.2 was not identified and is a dependency of war-1.0.0-SNAPSHOT");
    return false;
}
count = StringUtils.countMatches(oldReport, "pkg:maven/org.hibernate/hibernate-validator@5.1.0.Final");
if (count == 0) {
    System.out.println("org.hibernate:hibernate-validator:5.1.0.Final was not identified, but is a transitive dependency of the old war-1.0.0-SNAPSHOT");
    return false;
}

String newReport = FileUtils.readFileToString(new File(basedir, "new/target/dependency-check-report.xml"), Charset.defaultCharset().name());
count = StringUtils.countMatches(newReport, "pkg:maven/org.owasp.test.aggregate.issue-1527/war@1.0.0-SNAPSHOT");
if (count == 0) {
    System.out.println(String.format("war-1.0.0-SNAPSHOT was not identified"));
    return false;
}
count = StringUtils.countMatches(newReport, "pkg:maven/org.apache.james/apache-mime4j-core@0.7.2");
if (count == 0) {
    System.out.println("org.apache.james:apache-mime4j-core:0.7.2 was not identified and is a dependency of war-1.0.0-SNAPSHOT");
    return false;
}
count = StringUtils.countMatches(newReport, "pkg:maven/org.hibernate/hibernate-validator@5.1.2.Final");
if (count != 0) {
    System.out.println("org.hibernate:hibernate-validator:5.1.0.Final was identified, but was only a dependency of the old war-1.0.0-SNAPSHOT");
    return false;
}

return true;