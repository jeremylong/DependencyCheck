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
package org.owasp.dependencycheck.analyzer;

import java.util.Iterator;
import java.util.List;
import java.util.Set;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Identifier;

/**
 * This analyzer attempts to remove some well known false positives -
 * specifically regarding the java runtime.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class FalsePositiveAnalyzer extends AbstractAnalyzer {

    /**
     * The set of file extensions supported by this analyzer.
     */
    private static final Set<String> EXTENSIONS = null; //newHashSet("jar");
    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "False Positive Analyzer";
    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.POST_IDENTIFIER_ANALYSIS;

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
     * @param extension the file extension to test for support
     * @return whether or not the specified file extension is supported by this
     * analyzer.
     */
    public boolean supportsExtension(String extension) {
        return true; //EXTENSIONS.contains(extension);
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
     * a list of spring versions.
     */
    private List<Identifier> springVersions;

    /**
     *
     *
     * @param dependency the dependency to analyze.
     * @param engine the engine that is scanning the dependencies
     * @throws AnalysisException is thrown if there is an error reading the JAR
     * file.
     */
    public void analyze(Dependency dependency, Engine engine) throws AnalysisException {
        removeJreEntries(dependency);
        removeVersions(dependency);
    }

    /**
     * Intended to remove spurious CPE entries.
     *
     * @param dependency the dependency being analyzed
     */
    private void removeVersions(Dependency dependency) {
        //todo implement this so that the following is corrected?
        //cpe: cpe:/a:apache:axis2:1.4
        //cpe: cpe:/a:apache:axis:1.4
        /* the above was identified from the evidence below:
         Source    Name            Value
         Manifest  Bundle-Vendor   Apache Software Foundation
         Manifest  Bundle-Version  1.4
         file      name            axis2-kernel-1.4.1
         pom       artifactid      axis2-kernel
         pom       name            Apache Axis2 - Kernel
         */
    }

    /**
     * Removes any CPE entries for the JDK/JRE unless the filename ends with
     * rt.jar
     *
     * @param dependency the dependency to remove JRE CPEs from
     */
    private void removeJreEntries(Dependency dependency) {
        final List<Identifier> identifiers = dependency.getIdentifiers();
        final Iterator<Identifier> itr = identifiers.iterator();
        while (itr.hasNext()) {
            final Identifier i = itr.next();
            if ((i.getValue().startsWith("cpe:/a:sun:java:")
                    || i.getValue().startsWith("cpe:/a:oracle:jre")
                    || i.getValue().startsWith("cpe:/a:oracle:jdk"))
                    && !dependency.getFileName().toLowerCase().endsWith("rt.jar")) {
                itr.remove();
            }
        }
    }
}
