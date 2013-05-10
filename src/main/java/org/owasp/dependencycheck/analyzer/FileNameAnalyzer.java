/*
 * This file is part of Dependency-Check.
 *
 * Dependency-Check is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Check is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * DependencyCheck. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
import java.util.Set;
import org.owasp.dependencycheck.Engine;

/**
 *
 * Takes a dependency and analyzes the filename and determines the hashes.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class FileNameAnalyzer extends AbstractAnalyzer implements Analyzer {

    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "File Name Analyzer";
    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;
    /**
     * The set of file extensions supported by this analyzer.
     */
    private static final Set<String> EXTENSIONS = null;

    /**
     * Returns a list of file EXTENSIONS supported by this analyzer.
     *
     * @return a list of file EXTENSIONS supported by this analyzer.
     */
    public Set<String> getSupportedExtensions() {
        return EXTENSIONS;
    }

    /**
     * Returns the name of the analyzer.
     *
     * @return the name of the analyzer.
     */
    public String getName() {
        return ANALYZER_NAME;
    }

    /**
     * Returns whether or not this analyzer can process the given extension.
     *
     * @param extension the file extension to test for support.
     * @return whether or not the specified file extension is supported by this
     * analyzer.
     */
    public boolean supportsExtension(String extension) {
        return true;
    }

    /**
     * Returns the phase that the analyzer is intended to run in.
     *
     * @return the phase that the analyzer is intended to run in.
     */
    public AnalysisPhase getAnalysisPhase() {
        return ANALYSIS_PHASE;
    }

    /**
     * Collects information about the file name.
     *
     * @param dependency the dependency to analyze.
     * @param engine the engine that is scanning the dependencies
     * @throws AnalysisException is thrown if there is an error reading the JAR
     * file.
     */
    public void analyze(Dependency dependency, Engine engine) throws AnalysisException {

        String fileName = dependency.getFileName();
        final int pos = fileName.lastIndexOf(".");
        if (pos > 0) {
            fileName = fileName.substring(0, pos);
        }

        dependency.getProductEvidence().addEvidence("file", "name",
                fileName, Evidence.Confidence.HIGH);

        dependency.getVendorEvidence().addEvidence("file", "name",
                fileName, Evidence.Confidence.HIGH);

        if (fileName.matches(".*\\d.*")) {
            dependency.getVersionEvidence().addEvidence("file", "name",
                    fileName, Evidence.Confidence.HIGH);
        }
    }
}
