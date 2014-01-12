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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.Set;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class HintAnalyzer extends AbstractAnalyzer implements Analyzer {

    //<editor-fold defaultstate="collapsed" desc="All standard implmentation details of Analyzer">
    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Hint Analyzer";
    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.PRE_IDENTIFIER_ANALYSIS;
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
     * The HintAnalyzer uses knowledge about a dependency to add additional
     * information to help in identification of identifiers or vulnerabilities.
     *
     * @param dependency The dependency being analyzed
     * @param engine The scanning engine
     * @throws AnalysisException is thrown if there is an exception analyzing
     * the dependency.
     */
    @Override
    public void analyze(Dependency dependency, Engine engine) throws AnalysisException {
        final Evidence springTest1 = new Evidence("Manifest",
                "Implementation-Title",
                "Spring Framework",
                Evidence.Confidence.HIGH);

        final Evidence springTest2 = new Evidence("Manifest",
                "Implementation-Title",
                "org.springframework.core",
                Evidence.Confidence.HIGH);

        final Evidence springTest3 = new Evidence("Manifest",
                "Bundle-Vendor",
                "SpringSource",
                Evidence.Confidence.HIGH);


        Set<Evidence> evidence = dependency.getProductEvidence().getEvidence();
        if (evidence.contains(springTest1) || evidence.contains(springTest2)) {
            dependency.getProductEvidence().addEvidence("hint analyzer", "product", "springsource_spring_framework", Evidence.Confidence.HIGH);
            dependency.getVendorEvidence().addEvidence("hint analyzer", "vendor", "SpringSource", Evidence.Confidence.HIGH);
            dependency.getVendorEvidence().addEvidence("hint analyzer", "vendor", "vmware", Evidence.Confidence.HIGH);
        }

        evidence = dependency.getVendorEvidence().getEvidence();
        if (evidence.contains(springTest3)) {
            dependency.getProductEvidence().addEvidence("hint analyzer", "product", "springsource_spring_framework", Evidence.Confidence.HIGH);
            dependency.getVendorEvidence().addEvidence("hint analyzer", "vendor", "vmware", Evidence.Confidence.HIGH);
        }
        final Iterator<Evidence> itr = dependency.getVendorEvidence().iterator();
        final ArrayList<Evidence> newEntries = new ArrayList<Evidence>();
        while (itr.hasNext()) {
            final Evidence e = itr.next();
            if ("sun".equalsIgnoreCase(e.getValue(false))) {
                final Evidence newEvidence = new Evidence(e.getSource() + " (hint)", e.getName(), "oracle", e.getConfidence());
                newEntries.add(newEvidence);
            } else if ("oracle".equalsIgnoreCase(e.getValue(false))) {
                final Evidence newEvidence = new Evidence(e.getSource() + " (hint)", e.getName(), "sun", e.getConfidence());
                newEntries.add(newEvidence);
            }
        }
        for (Evidence e : newEntries) {
            dependency.getVendorEvidence().addEvidence(e);
        }


    }
}
