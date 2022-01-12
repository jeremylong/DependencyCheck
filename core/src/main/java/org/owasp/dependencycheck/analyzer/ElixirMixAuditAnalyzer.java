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
 * Copyright (c) 2020 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import us.springett.parsers.cpe.exceptions.CpeValidationException;
import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.apache.commons.lang3.StringUtils;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;
import org.owasp.dependencycheck.processing.MixAuditProcessor;
import org.owasp.dependencycheck.utils.processing.ProcessReader;

@Experimental
public class ElixirMixAuditAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(ElixirMixAuditAnalyzer.class);

    /**
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String DEPENDENCY_ECOSYSTEM = Ecosystem.ELIXIR;

    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Elixir Mix Audit Analyzer";

    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.PRE_INFORMATION_COLLECTION;
    /**
     * The filter defining which files will be analyzed.
     */
    private static final FileFilter FILTER = FileFilterBuilder.newInstance().addFilenames("mix.lock").build();
    /**
     * Name.
     */
    public static final String NAME = "Name: ";
    /**
     * Version.
     */
    public static final String VERSION = "Version: ";
    /**
     * Advisory.
     */
    public static final String ADVISORY = "Advisory: ";
    /**
     * Criticality.
     */
    public static final String CRITICALITY = "Criticality: ";
    /**
     * The DAL.
     */
    private CveDB cvedb = null;

    /**
     * @return a filter that accepts files named mix.lock
     */
    @Override
    protected FileFilter getFileFilter() {
        return FILTER;
    }

    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        if (engine != null) {
            this.cvedb = engine.getDatabase();
        }

        // Here we check if mix_audit actually runs from this location. We do this by running the
        // `mix_audit --version` command and seeing whether or not it succeeds (if it returns with an exit value of 0)
        final Process process;
        try {
            final List<String> mixAuditArgs = Arrays.asList("--version");
            process = launchMixAudit(getSettings().getTempDirectory(), mixAuditArgs);
        } catch (AnalysisException ae) {
            setEnabled(false);
            final String msg = String.format("Exception from mix_audit process: %s. Disabling %s", ae.getCause(), ANALYZER_NAME);
            throw new InitializationException(msg, ae);
        } catch (IOException ex) {
            setEnabled(false);
            throw new InitializationException("Unable to create temporary file, the Mix Audit Analyzer will be disabled", ex);
        }

        final int exitValue;
        final String mixAuditVersionDetails;
        try (ProcessReader processReader = new ProcessReader(process)) {
            processReader.readAll();
            exitValue = process.exitValue();

            if (exitValue != 0) {
                if (StringUtils.isBlank(processReader.getError())) {
                    LOGGER.warn("Unexpected exit value from mix_audit process and error stream unexpectedly not ready to capture error details. "
                            + "Disabling {}. Exit value was: {}", ANALYZER_NAME, exitValue);
                    setEnabled(false);
                    throw new InitializationException("mix_audit error stream unexpectedly not ready.");
                } else {
                    setEnabled(false);
                    LOGGER.warn("Unexpected exit value from mix_audit process. Disabling {}. Exit value was: {}. "
                            + "error stream output from mix_audit process was: {}", ANALYZER_NAME, exitValue, processReader.getError());
                    throw new InitializationException("Unexpected exit value from bundle-audit process.");
                }
            } else {
                if (StringUtils.isBlank(processReader.getOutput())) {
                    LOGGER.warn("mix_audit input stream unexpectedly not ready to capture version details. Disabling {}", ANALYZER_NAME);
                    setEnabled(false);
                    throw new InitializationException("mix_audit input stream unexpectedly not ready to capture version details.");
                } else {
                    mixAuditVersionDetails = processReader.getOutput();
                }
            }
        } catch (InterruptedException ex) {
            setEnabled(false);
            final String msg = String.format("mix_audit process was interrupted. Disabling %s", ANALYZER_NAME);
            Thread.currentThread().interrupt();
            throw new InitializationException(msg);
        } catch (IOException ex) {
            setEnabled(false);
            final String msg = String.format("IOException '%s' during mix_audit process was interrupted. Disabling %s",
                    ex.getMessage(), ANALYZER_NAME);
            throw new InitializationException(msg);
        }

        if (isEnabled()) {
            LOGGER.debug("{} is enabled and is using mix_audit with version: {}.", ANALYZER_NAME, mixAuditVersionDetails);
        }
    }

    /**
     * Returns the key used in the properties file to reference the analyzer's
     * enabled property.
     *
     * @return the analyzer's enabled property setting key
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_MIX_AUDIT_ENABLED;
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

    /**
     * Launch mix audit.
     *
     * @param folder directory that contains the mix.lock file
     * @param mixAuditArgs the arguments to pass to mix audit
     * @return a handle to the process
     * @throws AnalysisException thrown when there is an issue launching mix
     * audit
     */
    private Process launchMixAudit(File folder, List<String> mixAuditArgs) throws AnalysisException {
        if (!folder.isDirectory()) {
            throw new AnalysisException(String.format("%s should have been a directory.", folder.getAbsolutePath()));
        }

        final List<String> args = new ArrayList<>();
        final String mixAuditPath = getSettings().getString(Settings.KEYS.ANALYZER_MIX_AUDIT_PATH);
        File mixAudit = null;

        if (mixAuditPath != null) {
            mixAudit = new File(mixAuditPath);
            if (!mixAudit.isFile()) {
                LOGGER.warn("Supplied `mixAudit` path is incorrect: {}", mixAuditPath);
                mixAudit = null;
            }
        } else {
            final Path homePath = Paths.get(System.getProperty("user.home"));
            final Path escriptPath = Paths.get(homePath.toString(), ".mix", "escripts", "mix_audit");
            mixAudit = escriptPath.toFile();
        }

        args.add(mixAudit != null ? mixAudit.getAbsolutePath() : "mix_audit");
        args.addAll(mixAuditArgs);
        final ProcessBuilder builder = new ProcessBuilder(args);

        builder.directory(folder);
        try {
            LOGGER.info("Launching: {} from {}", args, folder);
            return builder.start();
        } catch (IOException ioe) {
            throw new AnalysisException("mix_audit initialization failure; this error can be ignored if you are not analyzing Elixir. "
                    + "Otherwise ensure that mix_audit is installed and the path to mix_audit is correctly specified", ioe);
        }
    }

    /**
     * Determines if the analyzer can analyze the given file type.
     *
     * @param dependency the dependency to determine if it can analyze
     * @param engine the dependency-check engine
     * @throws AnalysisException thrown if there is an analysis exception.
     */
    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine)
            throws AnalysisException {
        final File parentFile = dependency.getActualFile().getParentFile();
        final List<String> mixAuditArgs = Arrays.asList("--format", "json");

        final Process process = launchMixAudit(parentFile, mixAuditArgs);
        final int exitValue;
        try (MixAuditProcessor processor = new MixAuditProcessor(dependency, engine);
                ProcessReader processReader = new ProcessReader(process, processor)) {
            processReader.readAll();
            exitValue = process.exitValue();
            if (exitValue < 0 || exitValue > 1) {
                final String msg = String.format("Unexpected exit code from mix_audit process; exit code: %s", exitValue);
                throw new AnalysisException(msg);
            }
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new AnalysisException("mix_audit process interrupted", ie);
        } catch (IOException | CpeValidationException ioe) {
            LOGGER.warn("mix_audit failure", ioe);
            throw new AnalysisException("mix_audit failure", ioe);
        }
    }
}
