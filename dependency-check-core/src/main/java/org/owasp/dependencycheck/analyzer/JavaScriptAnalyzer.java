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
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;

/**
 *
 * Used to analyze a JavaScript file to gather information to aid in identification of a CPE identifier.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class JavaScriptAnalyzer extends AbstractFileTypeAnalyzer implements Analyzer, FileTypeAnalyzer {

    //<editor-fold defaultstate="collapsed" desc="All standard implmentation details of Analyzer">
    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "JavaScript Analyzer";
    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;
    /**
     * The set of file extensions supported by this analyzer.
     */
    private static final Set<String> EXTENSIONS = newHashSet("js");

    /**
     * Returns a list of file EXTENSIONS supported by this analyzer.
     *
     * @return a list of file EXTENSIONS supported by this analyzer.
     */
    @Override
    public Set<String> getSupportedExtensions() {
        return EXTENSIONS;
    }

    /**
     * Returns the name of the analyzer.
     *
     * @return the name of the analyzer.
     */
    @Override
    public String getName() {
        return ANALYZER_NAME;
    }

    /**
     * Returns the phase that the analyzer is intended to run in.
     *
     * @return the phase that the analyzer is intended to run in.
     */
    @Override
    public AnalysisPhase getAnalysisPhase() {
        return ANALYSIS_PHASE;
    }
    //</editor-fold>

    /**
     * Loads a specified JavaScript file and collects information from the copyright information contained within.
     *
     * @param dependency the dependency to analyze.
     * @param engine the engine that is scanning the dependencies
     * @throws AnalysisException is thrown if there is an error reading the JavaScript file.
     */
    @Override
    public void analyze(Dependency dependency, Engine engine) throws AnalysisException {
        BufferedReader fin = null;;
        try {
            //  /\*([^\*][^/]|[\r\n\f])+?\*/
            final Pattern extractComments = Pattern.compile("(/\\*([^*]|[\\r\\n]|(\\*+([^*/]|[\\r\\n])))*\\*+/)|(//.*)", Pattern.MULTILINE);
            File file = dependency.getActualFile();
            fin = new BufferedReader(new FileReader(file));
            StringBuilder sb = new StringBuilder(2000);
            String text;
            while ((text = fin.readLine()) != null) {
                sb.append(text);
            }
        } catch (FileNotFoundException ex) {
            final String msg = String.format("Dependency file not found: '%s'", dependency.getActualFilePath());
            throw new AnalysisException(msg, ex);
        } catch (IOException ex) {
            Logger.getLogger(JavaScriptAnalyzer.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            if (fin != null) {
                try {
                    fin.close();
                } catch (IOException ex) {
                    Logger.getLogger(JavaScriptAnalyzer.class.getName()).log(Level.FINEST, null, ex);
                }
            }
        }
    }
}
