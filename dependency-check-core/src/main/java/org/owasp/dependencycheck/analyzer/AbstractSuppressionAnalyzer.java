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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import java.io.File;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.owasp.dependencycheck.suppression.SuppressionParseException;
import org.owasp.dependencycheck.suppression.SuppressionParser;
import org.owasp.dependencycheck.suppression.SuppressionRule;
import org.owasp.dependencycheck.utils.Settings;

/**
 * Abstract base suppression analyzer that contains methods for parsing the suppression xml file.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public abstract class AbstractSuppressionAnalyzer extends AbstractAnalyzer {

    //<editor-fold defaultstate="collapsed" desc="All standard implementation details of Analyzer">
    /**
     * Returns a list of file EXTENSIONS supported by this analyzer.
     *
     * @return a list of file EXTENSIONS supported by this analyzer.
     */
    public Set<String> getSupportedExtensions() {
        return null;
    }

    /**
     * Returns whether or not this analyzer can process the given extension.
     *
     * @param extension the file extension to test for support.
     * @return whether or not the specified file extension is supported by this analyzer.
     */
    @Override
    public boolean supportsExtension(String extension) {
        return true;
    }

    //</editor-fold>
    /**
     * The initialize method loads the suppression XML file.
     *
     * @throws Exception thrown if there is an exception
     */
    @Override
    public void initialize() throws Exception {
        super.initialize();
        loadSuppressionData();
    }
    /**
     * The list of suppression rules
     */
    private List<SuppressionRule> rules;

    /**
     * Get the value of rules.
     *
     * @return the value of rules
     */
    public List<SuppressionRule> getRules() {
        return rules;
    }

    /**
     * Set the value of rules.
     *
     * @param rules new value of rules
     */
    public void setRules(List<SuppressionRule> rules) {
        this.rules = rules;
    }

    /**
     * Loads the suppression rules file.
     *
     * @throws SuppressionParseException thrown if the XML cannot be parsed.
     */
    private void loadSuppressionData() throws SuppressionParseException {
        final File file = Settings.getFile(Settings.KEYS.SUPPRESSION_FILE);
        if (file != null) {
            final SuppressionParser parser = new SuppressionParser();
            try {
                rules = parser.parseSuppressionRules(file);
            } catch (SuppressionParseException ex) {
                final String msg = String.format("Unable to parse suppression xml file '%s'", file.getPath());
                Logger.getLogger(AbstractSuppressionAnalyzer.class.getName()).log(Level.WARNING, msg);
                Logger.getLogger(AbstractSuppressionAnalyzer.class.getName()).log(Level.WARNING, ex.getMessage());
                Logger.getLogger(AbstractSuppressionAnalyzer.class.getName()).log(Level.FINE, null, ex);
                throw ex;
            }
        }
    }
}
