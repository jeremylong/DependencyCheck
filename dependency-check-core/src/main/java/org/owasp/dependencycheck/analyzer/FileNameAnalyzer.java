/*
 * This file is part of dependency-check-core.
 *
 * Dependency-check-core is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-check-core is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * dependency-check-core. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import java.io.File;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
import java.util.Set;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.utils.DependencyVersion;
import org.owasp.dependencycheck.utils.DependencyVersionUtil;

/**
 *
 * Takes a dependency and analyzes the filename and determines the hashes.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class FileNameAnalyzer extends AbstractAnalyzer implements Analyzer {

    //<editor-fold defaultstate="collapsed" desc="All standard implmentation details of Analyzer">
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
    //</editor-fold>

    /**
     * Collects information about the file name.
     *
     * @param dependency the dependency to analyze.
     * @param engine the engine that is scanning the dependencies
     * @throws AnalysisException is thrown if there is an error reading the JAR
     * file.
     */
    @Override
    public void analyze(Dependency dependency, Engine engine) throws AnalysisException {

        //strip any path information that may get added by ArchiveAnalyzer, etc.
        final File f = new File(dependency.getFileName());
        String fileName = f.getName();

        //remove file extension
        final int pos = fileName.lastIndexOf(".");
        if (pos > 0) {
            fileName = fileName.substring(0, pos);
        }

        //add version evidence
        final DependencyVersion version = DependencyVersionUtil.parseVersion(fileName);
        if (version != null) {
            dependency.getVersionEvidence().addEvidence("file", "name",
                    version.toString(), Evidence.Confidence.HIGHEST);
            dependency.getVersionEvidence().addEvidence("file", "name",
                    fileName, Evidence.Confidence.MEDIUM);
        }

        //add as vendor and product evidence
        if (fileName.contains("-")) {
            dependency.getProductEvidence().addEvidence("file", "name",
                    fileName, Evidence.Confidence.HIGHEST);
            dependency.getVendorEvidence().addEvidence("file", "name",
                    fileName, Evidence.Confidence.HIGHEST);
        } else {
            dependency.getProductEvidence().addEvidence("file", "name",
                    fileName, Evidence.Confidence.HIGH);
            dependency.getVendorEvidence().addEvidence("file", "name",
                    fileName, Evidence.Confidence.HIGH);
        }
    }
}
