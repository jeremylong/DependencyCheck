package org.codesecure.dependencycheck.scanner;
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

import java.io.File;
import java.io.IOException;
import java.util.Set;

/**
 * An interface that defines an Analyzer that is used to identify Dependencies.
 * An analyzer will collect information about the dependency in the form of
 * Evidence.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public interface Analyzer {

    /**
     * Loads a specified file and collects data needed to determine any associated CPE/CVE entries.
     *
     * @param file path to the file.
     * @return Dependency the dependency containing evidence needed to determine associated CPE/CVE entries.
     * @throws IOException is thrown if there is an error reading the dependency file
     */
    Dependency insepct(File file) throws IOException;
    
    /**
     * Returns a list of supported file extensions. An example would be an analyzer
     * that inpected java jar files. The getSupportedExtensions function would return
     * a set with a single element "jar".
     * 
     * @return The file extensions supported by this analyzer.
     */
    Set<String> getSupportedExtensions();
    
    /**
     * Returns the name of the analyzer.
     * @return the name of the analyzer.
     */
    String getName();
    
    /**
     * Returns whether or not this analyzer can process the given extension.
     * @param extension the file extension to test for support.
     * @return whether or not the specified file extension is supported by tihs analyzer.
     */
    boolean supportsExtension(String extension);
}
