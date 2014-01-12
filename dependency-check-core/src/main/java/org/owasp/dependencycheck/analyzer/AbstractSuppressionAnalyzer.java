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
 * Abstract base suppression analyzer that contains methods for parsing the
 * suppression xml file.
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
     * @return whether or not the specified file extension is supported by this
     * analyzer.
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
