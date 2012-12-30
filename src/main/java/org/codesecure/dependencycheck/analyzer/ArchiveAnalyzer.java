/*
 * This file is part of DependencyCheck.
 *
 * DependencyCheck is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * DependencyCheck is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * DependencyCheck. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.codesecure.dependencycheck.analyzer;

import org.codesecure.dependencycheck.dependency.Dependency;
import java.io.IOException;
import org.codesecure.dependencycheck.Engine;

/**
 * An interface that defines an Analyzer that is used to expand archives and
 * allow the engine to scan the contents.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public interface ArchiveAnalyzer {

    /**
     * An ArchiveAnalyzer expands an archive and calls the scan method of the
     * engine on the exploded contents.
     *
     * @param dependency a dependency to analyze.
     * @param engine the engine that is scanning the dependencies.
     * @throws IOException is thrown if there is an error reading the dependency
     * file
     */
    void analyze(Dependency dependency, Engine engine) throws IOException;

    /**
     * Cleans any temporary files generated when analyzing the archive.
     */
    void cleanup();
}
