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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.Set;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Confidence;
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
     * The HintAnalyzer uses knowledge about a dependency to add additional information to help in identification of
     * identifiers or vulnerabilities.
     *
     * @param dependency The dependency being analyzed
     * @param engine The scanning engine
     * @throws AnalysisException is thrown if there is an exception analyzing the dependency.
     */
    @Override
    public void analyze(Dependency dependency, Engine engine) throws AnalysisException {
        final Evidence springTest1 = new Evidence("Manifest",
                "Implementation-Title",
                "Spring Framework",
                Confidence.HIGH);

        final Evidence springTest2 = new Evidence("Manifest",
                "Implementation-Title",
                "org.springframework.core",
                Confidence.HIGH);

        final Evidence springTest3 = new Evidence("Manifest",
                "Bundle-Vendor",
                "SpringSource",
                Confidence.HIGH);

        Set<Evidence> evidence = dependency.getProductEvidence().getEvidence();
        if (evidence.contains(springTest1) || evidence.contains(springTest2)) {
            dependency.getProductEvidence().addEvidence("hint analyzer", "product", "springsource_spring_framework", Confidence.HIGH);
            dependency.getVendorEvidence().addEvidence("hint analyzer", "vendor", "SpringSource", Confidence.HIGH);
            dependency.getVendorEvidence().addEvidence("hint analyzer", "vendor", "vmware", Confidence.HIGH);
        }

        evidence = dependency.getVendorEvidence().getEvidence();
        if (evidence.contains(springTest3)) {
            dependency.getProductEvidence().addEvidence("hint analyzer", "product", "springsource_spring_framework", Confidence.HIGH);
            dependency.getVendorEvidence().addEvidence("hint analyzer", "vendor", "vmware", Confidence.HIGH);
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
