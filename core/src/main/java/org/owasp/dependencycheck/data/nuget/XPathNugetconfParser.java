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
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nuget;

import java.io.IOException;
import java.io.InputStream;
import javax.annotation.concurrent.ThreadSafe;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import org.owasp.dependencycheck.utils.XmlUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

/**
 * Parse a Nugetconf file using XPath.
 *
 * @author colezlaw
 */
@ThreadSafe
public class XPathNugetconfParser implements NugetconfParser {

    /**
     * Gets the string value of a node or null if it's not present
     *
     * @param n the node to test
     * @return the string content of the node, or null if the node itself is
     * null
     */
    private String getOrNull(Node n) {
        if (n != null) {
            return n.getTextContent();
        } else {
            return null;
        }
    }

    /**
     * Parse an input stream and return the resulting {@link NugetPackage}.
     *
     * @param stream the input stream to parse
     * @return the populated bean
     * @throws NugetconfParseException when an exception occurs
     */
    @Override
    public NugetPackage parse(InputStream stream) throws NugetconfParseException {
        try {
            final DocumentBuilder db = XmlUtils.buildSecureDocumentBuilder();
            final Document d = db.parse(stream);

            final XPath xpath = XPathFactory.newInstance().newXPath();
            final NugetPackage nugetconf = new NugetPackage();

            if (xpath.evaluate("/package/metadata/id", d, XPathConstants.NODE) == null
                    || xpath.evaluate("/package/metadata/version", d, XPathConstants.NODE) == null
                    || xpath.evaluate("/package/metadata/authors", d, XPathConstants.NODE) == null
                    || xpath.evaluate("/package/metadata/description", d, XPathConstants.NODE) == null) {
                throw new NugetconfParseException("Invalid packages.config format");
            }

            nugetconf.setId(xpath.evaluate("/package/metadata/id", d));
            nugetconf.setVersion(xpath.evaluate("/package/metadata/version", d));
            nugetconf.setAuthors(xpath.evaluate("/package/metadata/authors", d));
            nugetconf.setOwners(getOrNull((Node) xpath.evaluate("/package/metadata/owners", d, XPathConstants.NODE)));
            nugetconf.setLicenseUrl(getOrNull((Node) xpath.evaluate("/package/metadata/licenseUrl", d, XPathConstants.NODE)));
            nugetconf.setTitle(getOrNull((Node) xpath.evaluate("/package/metadata/title", d, XPathConstants.NODE)));
            return nugetconf;
        } catch (ParserConfigurationException | SAXException | IOException | XPathExpressionException | NugetconfParseException e) {
            throw new NugetconfParseException("Unable to parse packages.config", e);
        }
    }
}
