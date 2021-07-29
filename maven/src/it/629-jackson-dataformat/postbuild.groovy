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

import org.apache.commons.io.FileUtils
import org.w3c.dom.NodeList;

import java.nio.charset.Charset;
import javax.xml.xpath.*
import javax.xml.parsers.DocumentBuilderFactory

def countMatches(String xml, String xpathQuery) {
    def xpath = XPathFactory.newInstance().newXPath()
    def builder     = DocumentBuilderFactory.newInstance().newDocumentBuilder()
    def inputStream = new ByteArrayInputStream( xml.bytes )
    def records     = builder.parse(inputStream).documentElement
    NodeList nodes       = xpath.evaluate( xpathQuery, records, XPathConstants.NODESET ) as NodeList
    nodes.getLength();
}

// Check to see if jackson-dataformat-cbor-2.10.0.jar was identified with issue while suppressing it for jackson-dataformat-ion-2.10.0.jar
// both of which map to cpe:2.3:a:fasterxml:jackson-dataformats-binary
//
String log = FileUtils.readFileToString(new File(basedir, "target/dependency-check-report.xml"), Charset.defaultCharset().name());
int count = countMatches(log,"/analysis/dependencies/dependency[./fileName = 'jackson-dataformat-cbor-2.10.0.jar']/vulnerabilities/vulnerability[./name = 'CVE-2020-28491']");
if (count != 1){
    System.out.println(String.format("jackson-dataformat-cbor CVE-2020-28491 was identified %s times, expected 1", count));
    return false;
}
count = countMatches(log,"/analysis/dependencies/dependency[./fileName = 'jackson-dataformat-ion-2.10.0.jar']/vulnerabilities/vulnerability[./name = 'CVE-2020-28491']");
if (count != 0){
    System.out.println(String.format("jackson-dataformat-ion CVE-2020-28491 was identified %s times, expected 0", count));
    return false;
}
count = countMatches(log,"/analysis/dependencies/dependency[./fileName = 'jackson-dataformat-ion-2.10.0.jar']");
if (count != 1){
    System.out.println(String.format("jackson-dataformat-ion dependency was identified %s times, expected 1", count));
    return false;
}
return true;
