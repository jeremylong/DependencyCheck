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
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Pattern;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.xml.suppression.PropertyType;
import org.owasp.dependencycheck.utils.DownloadFailedException;
import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.xml.hints.VendorDuplicatingHintRule;
import org.owasp.dependencycheck.xml.hints.HintParseException;
import org.owasp.dependencycheck.xml.hints.HintParser;
import org.owasp.dependencycheck.xml.hints.HintRule;
import org.owasp.dependencycheck.xml.hints.Hints;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

/**
 * This analyzer adds evidence to dependencies to enhance the accuracy of
 * library identification.
 *
 * @author Jeremy Long
 */
public class HintAnalyzer extends AbstractAnalyzer {

    /**
     * The Logger for use throughout the class
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(HintAnalyzer.class);
    /**
     * The name of the hint rule file
     */
    private static final String HINT_RULE_FILE_NAME = "dependencycheck-base-hint.xml";
    /**
     * The collection of hints.
     */
    private Hints hints;

    //<editor-fold defaultstate="collapsed" desc="All standard implementation details of Analyzer">
    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Hint Analyzer";
    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.PRE_IDENTIFIER_ANALYSIS;

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

    /**
     * <p>
     * Returns the setting key to determine if the analyzer is enabled.</p>
     *
     * @return the key for the analyzer's enabled property
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_HINT_ENABLED;
    }

    /**
     * The initialize method does nothing for this Analyzer.
     *
     * @throws InitializationException thrown if there is an exception
     */
    @Override
    public void initializeAnalyzer() throws InitializationException {
        try {
            loadHintRules();
        } catch (HintParseException ex) {
            LOGGER.debug("Unable to parse hint file", ex);
            throw new InitializationException("Unable to parse the hint file", ex);
        }
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
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        for (HintRule hint : hints.getHintRules()) {
            boolean matchFound = false;
            for (Evidence given : hint.getGivenVendor()) {
                if (dependency.getVendorEvidence().getEvidence().contains(given)) {
                    matchFound = true;
                    break;
                }
            }
            if (!matchFound) {
                for (Evidence given : hint.getGivenProduct()) {
                    if (dependency.getProductEvidence().getEvidence().contains(given)) {
                        matchFound = true;
                        break;
                    }
                }
            }
            if (!matchFound) {
                for (Evidence given : hint.getGivenVersion()) {
                    if (dependency.getVersionEvidence().getEvidence().contains(given)) {
                        matchFound = true;
                        break;
                    }
                }
            }
            if (!matchFound) {
                for (PropertyType pt : hint.getFilenames()) {
                    if (pt.matches(dependency.getFileName())) {
                        matchFound = true;
                        break;
                    }
                }
            }
            if (matchFound) {
                for (Evidence e : hint.getAddVendor()) {
                    dependency.getVendorEvidence().addEvidence(e);
                }
                for (Evidence e : hint.getAddProduct()) {
                    dependency.getProductEvidence().addEvidence(e);
                }
                for (Evidence e : hint.getAddVersion()) {
                    dependency.getVersionEvidence().addEvidence(e);
                }
                for (Evidence e : hint.getRemoveVendor()) {
                    if (dependency.getVendorEvidence().getEvidence().contains(e)) {
                        dependency.getVendorEvidence().getEvidence().remove(e);
                    }
                }
                for (Evidence e : hint.getRemoveProduct()) {
                    if (dependency.getProductEvidence().getEvidence().contains(e)) {
                        dependency.getProductEvidence().getEvidence().remove(e);
                    }
                }
                for (Evidence e : hint.getRemoveVersion()) {
                    if (dependency.getVersionEvidence().getEvidence().contains(e)) {
                        dependency.getVersionEvidence().getEvidence().remove(e);
                    }
                }
            }
        }

        final Iterator<Evidence> itr = dependency.getVendorEvidence().iterator();
        final List<Evidence> newEntries = new ArrayList<>();
        while (itr.hasNext()) {
            final Evidence e = itr.next();
            for (VendorDuplicatingHintRule dhr : hints.getVendorDuplicatingHintRules()) {
                if (dhr.getValue().equalsIgnoreCase(e.getValue(false))) {
                    newEntries.add(new Evidence(e.getSource() + " (hint)",
                            e.getName(), dhr.getDuplicate(), e.getConfidence()));
                }
            }
        }
        for (Evidence e : newEntries) {
            dependency.getVendorEvidence().addEvidence(e);
        }
    }

    /**
     * Loads the hint rules file.
     *
     * @throws HintParseException thrown if the XML cannot be parsed.
     */
    private void loadHintRules() throws HintParseException {
        final HintParser parser = new HintParser();
        File file = null;
        try {
            hints = parser.parseHints(this.getClass().getClassLoader().getResourceAsStream(HINT_RULE_FILE_NAME));
        } catch (HintParseException | SAXException ex) {
            LOGGER.error("Unable to parse the base hint data file");
            LOGGER.debug("Unable to parse the base hint data file", ex);
        }
        final String filePath = Settings.getString(Settings.KEYS.HINTS_FILE);
        if (filePath == null) {
            return;
        }
        boolean deleteTempFile = false;
        try {
            final Pattern uriRx = Pattern.compile("^(https?|file)\\:.*", Pattern.CASE_INSENSITIVE);
            if (uriRx.matcher(filePath).matches()) {
                deleteTempFile = true;
                file = FileUtils.getTempFile("hint", "xml");
                final URL url = new URL(filePath);
                try {
                    Downloader.fetchFile(url, file, false);
                } catch (DownloadFailedException ex) {
                    Downloader.fetchFile(url, file, true);
                }
            } else {
                file = new File(filePath);
                if (!file.exists()) {
                    try (InputStream fromClasspath = this.getClass().getClassLoader().getResourceAsStream(filePath)) {
                        if (fromClasspath != null) {
                            deleteTempFile = true;
                            file = FileUtils.getTempFile("hint", "xml");
                            try {
                                org.apache.commons.io.FileUtils.copyInputStreamToFile(fromClasspath, file);
                            } catch (IOException ex) {
                                throw new HintParseException("Unable to locate hints file in classpath", ex);
                            }
                        }
                    }
                }
            }

            if (file != null) {
                try {
                    final Hints newHints = parser.parseHints(file);
                    hints.getHintRules().addAll(newHints.getHintRules());
                    hints.getVendorDuplicatingHintRules().addAll(newHints.getVendorDuplicatingHintRules());
                    LOGGER.debug("{} hint rules were loaded.", hints.getHintRules().size());
                    LOGGER.debug("{} duplicating hint rules were loaded.", hints.getVendorDuplicatingHintRules().size());
                } catch (HintParseException ex) {
                    LOGGER.warn("Unable to parse hint rule xml file '{}'", file.getPath());
                    LOGGER.warn(ex.getMessage());
                    LOGGER.debug("", ex);
                    throw ex;
                }
            }
        } catch (DownloadFailedException ex) {
            throw new HintParseException("Unable to fetch the configured hint file", ex);
        } catch (MalformedURLException ex) {
            throw new HintParseException("Configured hint file has an invalid URL", ex);
        } catch (IOException ex) {
            throw new HintParseException("Unable to create temp file for hints", ex);
        } finally {
            if (deleteTempFile && file != null) {
                FileUtils.delete(file);
            }
        }
    }
}
