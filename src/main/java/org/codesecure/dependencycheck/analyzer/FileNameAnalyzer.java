package org.codesecure.dependencycheck.analyzer;
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

import org.codesecure.dependencycheck.dependency.Dependency;
import org.codesecure.dependencycheck.dependency.Evidence;
import java.io.IOException;
import java.util.Set;
import java.util.regex.Pattern;

/**
 *
 * Takes a dependency and analyzes the filename and determines the hashes.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class FileNameAnalyzer implements Analyzer {

    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "File Analyzer";
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
     * @return a list of file EXTENSIONS supported by this analyzer.
     */
    public Set<String> getSupportedExtensions() {
        return EXTENSIONS;
    }

    /**
     * Returns the name of the analyzer.
     * @return the name of the analyzer.
     */
    public String getName() {
        return ANALYZER_NAME;
    }

    /**
     * Returns whether or not this analyzer can process the given extension.
     * @param extension the file extension to test for support.
     * @return whether or not the specified file extension is supported by tihs analyzer.
     */
    public boolean supportsExtension(String extension) {
        return true;
    }

    /**
     * Returns the phase that the analyzer is intended to run in.
     * @return the phase that the analyzer is intended to run in.
     */
    public AnalysisPhase getAnalysisPhase() {
        return ANALYSIS_PHASE;
    }

    /**
     * An enumeration to keep track of the characters in a string as it is being
     * read in one character at a time.
     */
    private enum STRING_STATE {

        ALPHA,
        NUMBER,
        PERIOD,
        OTHER
    }

    /**
     * Determines type of the character passed in.
     * @param c a character
     * @return a STRING_STATE representing whether the character is number, alpha, or other.
     */
    private STRING_STATE determineState(char c) {
        if (c >= '0' && c <= '9') {
            return STRING_STATE.NUMBER;
        } else if (c == '.') {
            return STRING_STATE.PERIOD;
        } else if (c >= 'a' && c <= 'z') {
            return STRING_STATE.ALPHA;
        } else {
            return STRING_STATE.OTHER;
        }
    }

    /**
     * Collects information about the file such as hashsums.
     *
     * @param dependency the dependency to analyze.
     * @throws IOException is thrown if there is an error reading the JAR file.
     */
    public void analyze(Dependency dependency) throws IOException {

        analyzeFileName(dependency);

    }

    /**
     * Analyzes the filename of the dependency and adds it to the evidence collections.
     * @param dependency the dependency to analyze.
     */
    private void analyzeFileName(Dependency dependency) {
        String fileName = dependency.getFileName();
        //slightly process the filename to chunk it into distinct words, numbers.
        // Yes, the lucene analyzer might do this, but I want a little better control
        // over the process.
        String fileNameEvidence = fileName.substring(0, fileName.length() - 4).toLowerCase().replace('-', ' ').replace('_', ' ');
        StringBuilder sb = new StringBuilder(fileNameEvidence.length());
        STRING_STATE state = determineState(fileNameEvidence.charAt(0));

        for (int i = 0; i < fileNameEvidence.length(); i++) {
            char c = fileNameEvidence.charAt(i);
            STRING_STATE newState = determineState(c);
            if (newState != state) {
                if ((state != STRING_STATE.NUMBER && newState == STRING_STATE.PERIOD)
                        || (state == STRING_STATE.PERIOD && newState != STRING_STATE.NUMBER)
                        || (state == STRING_STATE.ALPHA || newState == STRING_STATE.ALPHA)
                        || ((state == STRING_STATE.OTHER || newState == STRING_STATE.OTHER) && c != ' ')) {
                    sb.append(' ');
                }
            }
            state = newState;
            sb.append(c);
        }
        Pattern rx = Pattern.compile("\\s\\s+");
        fileNameEvidence = rx.matcher(sb.toString()).replaceAll(" ");
        dependency.getProductEvidence().addEvidence("file", "name",
                fileNameEvidence, Evidence.Confidence.HIGH);
        dependency.getVendorEvidence().addEvidence("file", "name",
                fileNameEvidence, Evidence.Confidence.HIGH);
        if (fileNameEvidence.matches(".*\\d.*")) {
            dependency.getVersionEvidence().addEvidence("file", "name",
                    fileNameEvidence, Evidence.Confidence.HIGH);
        }
    }


    /**
     * The initialize method does nothing for this Analyzer
     */
    public void initialize() {
        //do nothing
    }

    /**
     * The close method does nothing for this Analyzer
     */
    public void close() {
        //do nothing
    }
}
