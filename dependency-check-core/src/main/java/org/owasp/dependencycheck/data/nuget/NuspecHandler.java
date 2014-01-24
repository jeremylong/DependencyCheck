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

import java.util.logging.Level;
import java.util.logging.Logger;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

/**
 * A <code>DefaultHandler</code> for parsing a Nuspec
 * file.
 */
public class NuspecHandler extends DefaultHandler {
    private String id;
    private String version;
    private String title;
    private String authors;
    private String owners;
    private String licenseUrl;

    private boolean inId;
    private boolean inVersion;
    private boolean inTitle;
    private boolean inAuthors;
    private boolean inOwners;
    private boolean inLicenseUrl;

    private static final String NS_NUSPEC =
        "http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd";

    private static final Logger LOGGER = Logger.getLogger(NuspecHandler.class.getName());

    /**
     * Creates a NugetHandler
     */
    public NuspecHandler() {
        inId = inVersion = inTitle = inAuthors = inOwners = inLicenseUrl = false;
    }
  
    /**
     * Gets the id.
     * @return the id
     */
    public String getId() {
        return id;
    }

    /**
     * Gets the version.
     */
    public String getVersion() {
        return version;
    }

    /**
     * Gets the title.
     */
    public String getTitle() {
        return title;
    }

    /**
     * Gets the authors.
     */
    public String getAuthors() {
        return authors;
    }

    /**
     * Gets the owners.
     */
    public String getOwners() {
        return owners;
    }

    /**
     * Gets the licenseUrl;
     */
    public String getLicenseUrl() {
        return licenseUrl;
    }
    
    /**
     * Receive notification of the start of an element.
     * @param uri The Namespace URL, or the empty string if the element has no
     *            Namespace URI or if Namespace processing is not being
     *            performed.
     * @param localName The loca name (without prefix), or the empty string if
     *                  Namespace processing is not being performed.
     * @param qName The qualified name (with prefix), or the empty string if
     *              qualified names are not available.
     * @param attributes The attributes attached to the element. If there are
     *                   no attributes, it shall be an empty Attributes object.
     * @throws SAXException Any SAX exception, possibly wrapping another
     *                      exception.
     */
    public void startElement(String uri, String localName, String qName,
                             Attributes attributes) throws SAXException {
        if (NS_NUSPEC.equals(uri) && "id".equals(localName)) {
            id = "";
            inId = true;
        } else if (NS_NUSPEC.equals(uri) && "version".equals(localName)) {
            version = "";
            inVersion = true;
        } else if (NS_NUSPEC.equals(uri) && "title".equals(localName)) {
            title = "";
            inTitle = true;
        } else if (NS_NUSPEC.equals(uri) && "authors".equals(localName)) {
            authors = "";
            inAuthors = true;
        } else if (NS_NUSPEC.equals(uri) && "owners".equals(localName)) {
            owners = "";
            inOwners = true;
        } else if (NS_NUSPEC.equals(uri) && "licenseUrl".equals(localName)) {
            licenseUrl = "";
            inLicenseUrl = true;
        }
    }

    /**
     * Receive notification of the end of an element.
     * By default, do nothing. Application writers may override this method in
     * a subclass to take specific actions at the end of each element (such as
     * finalising a tree node or writing output to a file).
     * @param uri The Namespace URI, or the empty string if the element has no
     *            Namespace URI or if Namespace processing is not being
     *            performed.
     * @param localName The local name (without prefix), or the empty string if
     *                  Namespace processing is not being performed.
     * @param qName The qualified name (with prefix), or the empty string if
     *              qualified names are not available.
     * @throws SAXException Any SAX exception, possibly wrapping another
     *                      exception.
     */
    public void endElement(String uri, String localName, String qName)
                           throws SAXException {
        inId = inVersion = inTitle = inAuthors = inOwners = inLicenseUrl = false;
    }

    /**
     * Receive notification of character data inside an element.
     * By default, do nothing. Application writers may override this method to
     * take specific actions for each chunk of character data (such as adding
     * the data to a node or buffer, or printing it to a file).
     * @param ch The characters.
     * @param start The start position in the character array.
     * @param length The number of characters to use from the character array.
     * @throws SAXException Any SAX exception, possibly wrapping another
     *                      exception.
     */
    public void characters(char[] ch, int start, int length)
                            throws SAXException {
        String toAppend = new String(ch, start, length);
        if (inId) {
            id += toAppend;
        } else if (inVersion) {
            version += toAppend;
        } else if (inTitle) {
            title += toAppend;
        } else if (inAuthors) {
            authors += toAppend;
        } else if (inOwners) {
            owners += toAppend;
        } else if (inLicenseUrl) {
            licenseUrl += toAppend;
        }
    }
}

// vim: cc=120:sw=4:ts=4:sts=4
