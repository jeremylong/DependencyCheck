package org.codesecure.dependencycheck.data;
/*
 * This file is part of DependencyCheck.
 *
 * DependencyCheck is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * DependencyCheck is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with DependencyCheck. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */


import java.io.IOException;
import java.net.MalformedURLException;
import javax.xml.parsers.ParserConfigurationException;
import org.xml.sax.SAXException;

/**
 * Defines an Index who's data is retrieved from the Internet. This data can
 * be downloaded and the index updated.
 * 
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public interface WebDataIndex {

    /**
     * Determines if an update to the current index is needed, if it is the new
     * data is downloaded from the Internet and imported into the current Lucene Index.
     *
     * @throws MalformedURLException is thrown if the URL for the CPE is malformed.
     * @throws ParserConfigurationException is thrown if the parser is misconfigured.
     * @throws SAXException is thrown if there is an error parsing the CPE XML.
     * @throws IOException is thrown if a temporary file could not be created.
     */
    public void updateIndexFromWeb() throws MalformedURLException, ParserConfigurationException, SAXException, IOException;
}
