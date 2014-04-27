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

import org.owasp.dependencycheck.suppression.SuppressionParseException;
import org.owasp.dependencycheck.suppression.SuppressionParser;
import org.owasp.dependencycheck.suppression.SuppressionRule;
import org.owasp.dependencycheck.utils.DownloadFailedException;
import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencycheck.utils.Settings;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * Abstract base suppression analyzer that contains methods for parsing the suppression xml file.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public abstract class AbstractSuppressionAnalyzer extends AbstractAnalyzer {

    /**
     * The Logger for use throughout the class
     */
    private static final Logger LOGGER = Logger.getLogger(AbstractSuppressionAnalyzer.class.getName());

    //<editor-fold defaultstate="collapsed" desc="All standard implementation details of Analyzer">

    /**
     * Returns a list of file EXTENSIONS supported by this analyzer.
     *
     * @return a list of file EXTENSIONS supported by this analyzer.
     */
    public Set<String> getSupportedExtensions() {
        return null;
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
        final String suppressionFilePath = Settings.getString(Settings.KEYS.SUPPRESSION_FILE);
        if (suppressionFilePath == null) {
            return;
        }
        File file = null;
        boolean deleteTempFile = false;
        try {
            final Pattern uriRx = Pattern.compile("^(https?|file)\\:.*", Pattern.CASE_INSENSITIVE);
            if (uriRx.matcher(suppressionFilePath).matches()) {
                deleteTempFile = true;
                file = FileUtils.getTempFile("suppression", "xml");
                final URL url = new URL(suppressionFilePath);
                try {
                    Downloader.fetchFile(url, file, false);
                } catch (DownloadFailedException ex) {
                    Downloader.fetchFile(url, file, true);
                }
            } else {
                file = new File(suppressionFilePath);
                if (!file.exists()) {
                    InputStream suppressionsFromClasspath = this.getClass().getClassLoader().getResourceAsStream(suppressionFilePath);
                    if (suppressionsFromClasspath != null) {
                        deleteTempFile = true;
                        file = FileUtils.getTempFile("suppression", "xml");
                        try {
                            org.apache.commons.io.FileUtils.copyInputStreamToFile(suppressionsFromClasspath, file);
                        } catch (IOException ex) {
                            throwSuppressionParseException("Unable to locate suppressions file in classpath", ex);
                        }
                    }
                }
            }

            if (file != null) {
                final SuppressionParser parser = new SuppressionParser();
                try {
                    rules = parser.parseSuppressionRules(file);
                    LOGGER.log(Level.FINE, rules.size() + " suppression rules were loaded.");
                } catch (SuppressionParseException ex) {
                    final String msg = String.format("Unable to parse suppression xml file '%s'", file.getPath());
                    LOGGER.log(Level.WARNING, msg);
                    LOGGER.log(Level.WARNING, ex.getMessage());
                    LOGGER.log(Level.FINE, "", ex);
                    throw ex;
                }
            }
        } catch (DownloadFailedException ex) {
            throwSuppressionParseException("Unable to fetch the configured suppression file", ex);
        } catch (MalformedURLException ex) {
            throwSuppressionParseException("Configured suppression file has an invalid URL", ex);
        } catch (IOException ex) {
            throwSuppressionParseException("Unable to create temp file for suppressions", ex);
        } finally {
            if (deleteTempFile && file != null) {
                FileUtils.delete(file);
            }
        }
    }

    private void throwSuppressionParseException(String message, Exception exception) throws SuppressionParseException {
        LOGGER.log(Level.WARNING, message);
        LOGGER.log(Level.FINE, "", exception);
        throw new SuppressionParseException(message, exception);
    }
}
