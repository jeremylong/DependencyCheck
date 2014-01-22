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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import java.io.File;
import java.util.Set;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
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
     * @return whether or not the specified file extension is supported by this analyzer.
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
     * @throws AnalysisException is thrown if there is an error reading the JAR file.
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
            // If the version number is just a number like 2 or 23, reduce the confidence
            // a shade. This should hopefully correct for cases like log4j.jar or
            // struts2-core.jar
            if (version.getVersionParts() == null || version.getVersionParts().size() < 2) {
                dependency.getVersionEvidence().addEvidence("file", "name",
                        version.toString(), Confidence.MEDIUM);
            } else {
                dependency.getVersionEvidence().addEvidence("file", "name",
                        version.toString(), Confidence.HIGHEST);
            }
            dependency.getVersionEvidence().addEvidence("file", "name",
                    fileName, Confidence.MEDIUM);
        }

        //add as vendor and product evidence
        if (fileName.contains("-")) {
            dependency.getProductEvidence().addEvidence("file", "name",
                    fileName, Confidence.HIGHEST);
            dependency.getVendorEvidence().addEvidence("file", "name",
                    fileName, Confidence.HIGHEST);
        } else {
            dependency.getProductEvidence().addEvidence("file", "name",
                    fileName, Confidence.HIGH);
            dependency.getVendorEvidence().addEvidence("file", "name",
                    fileName, Confidence.HIGH);
        }
    }
}
