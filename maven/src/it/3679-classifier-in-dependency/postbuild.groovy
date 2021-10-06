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

import org.apache.commons.io.FileUtils;
import org.w3c.dom.NodeList;

import java.nio.charset.Charset;
import javax.xml.xpath.*
import javax.xml.parsers.DocumentBuilderFactory

// Check to see if jackson-databind-2.5.3.jar was identified with a known CVE - using CVE-2018-7489.

def countMatches(String xml, String xpathQuery) {
    def xpath = XPathFactory.newInstance().newXPath()
    def builder     = DocumentBuilderFactory.newInstance().newDocumentBuilder()
    def inputStream = new ByteArrayInputStream( xml.bytes )
    def records     = builder.parse(inputStream).documentElement
    NodeList nodes       = xpath.evaluate( xpathQuery, records, XPathConstants.NODESET ) as NodeList
    nodes.getLength();
}

String log = FileUtils.readFileToString(new File(basedir, "target/dependency-check-report.xml"), Charset.defaultCharset().name());
int count = countMatches(log,"/analysis/dependencies/dependency[./fileName = 'guice-4.2.2-no_aop.jar']");
if (count != 1){
    System.out.println(String.format("google guice no_aop was identified %s times, expected 1", count));
    return false;
}
return true;
