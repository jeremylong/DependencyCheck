/*
 * This file is part of dependency-check-core.
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
 * Copyright (c) 2018 Paul Irwin. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nuget;

import org.owasp.dependencycheck.utils.XmlUtils;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Parses a MSBuild project file for NuGet references using XPath.
 *
 * @author paulirwin
 */
public class XPathMSBuildProjectParser implements MSBuildProjectParser {

    /**
     * Parses the given stream for MSBuild PackageReference elements.
     *
     * @param stream the input stream to parse
     * @return a collection of discovered NuGet package references
     * @throws MSBuildProjectParseException if an exception occurs
     */
    @Override
    public List<NugetPackageReference> parse(InputStream stream) throws MSBuildProjectParseException {
        try {
            final DocumentBuilder db = XmlUtils.buildSecureDocumentBuilder();
            final Document d = db.parse(stream);

            final XPath xpath = XPathFactory.newInstance().newXPath();
            final List<NugetPackageReference> packages = new ArrayList<>();

            final NodeList nodeList = (NodeList) xpath.evaluate("//PackageReference", d, XPathConstants.NODESET);

            if (nodeList == null) {
                throw new MSBuildProjectParseException("Unable to parse MSBuild project file");
            }

            for (int i = 0; i < nodeList.getLength(); i++) {
                final Node node = nodeList.item(i);
                final NamedNodeMap attrs = node.getAttributes();

                final Node include = attrs.getNamedItem("Include");
                final Node version = attrs.getNamedItem("Version");

                if (include != null && version != null) {
                    final NugetPackageReference npr = new NugetPackageReference();

                    npr.setId(include.getNodeValue());
                    npr.setVersion(version.getNodeValue());

                    packages.add(npr);
                }
            }

            return packages;
        } catch (ParserConfigurationException | SAXException | IOException | XPathExpressionException | MSBuildProjectParseException e) {
            throw new MSBuildProjectParseException("Unable to parse MSBuild project file", e);
        }
    }

}
