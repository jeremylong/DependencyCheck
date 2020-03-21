package org.owasp.dependencycheck.analyzer;

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
 * Copyright (c) 2020 OWASP. All Rights Reserved.
 */

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;
import com.google.common.collect.ImmutableList;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.elixir.MixAuditJsonParser;
import org.owasp.dependencycheck.data.elixir.MixAuditResult;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.dependency.*;
import org.owasp.dependencycheck.dependency.naming.GenericIdentifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.Checksum;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import us.springett.parsers.cpe.exceptions.CpeValidationException;
import us.springett.parsers.cpe.values.Part;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

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
    public static final String DEPENDENCY_ECOSYSTEM = "elixir";

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
            final List<String> mixAuditArgs = ImmutableList.of("--version");
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
        try {
            exitValue = process.waitFor();
        } catch (InterruptedException ex) {
            setEnabled(false);
            final String msg = String.format("mix_audit process was interrupted. Disabling %s", ANALYZER_NAME);
            Thread.currentThread().interrupt();
            throw new InitializationException(msg);
        }

        final String mixAuditVersionDetails;
        if (exitValue != 0) {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getErrorStream(), StandardCharsets.UTF_8))) {
                if (!reader.ready()) {
                    LOGGER.warn("Unexpected exit value from mix_audit process and error stream unexpectedly not ready to capture error details. "
                            + "Disabling {}. Exit value was: {}", ANALYZER_NAME, exitValue);
                    setEnabled(false);
                    throw new InitializationException("mix_audit error stream unexpectedly not ready.");
                } else {
                    final String line = reader.readLine();
                    setEnabled(false);
                    LOGGER.warn("Unexpected exit value from mix_audit process. Disabling {}. Exit value was: {}. "
                            + "error stream output from mix_audit process was: {}", ANALYZER_NAME, exitValue, line);
                    throw new InitializationException("Unexpected exit value from bundle-audit process.");
                }
            } catch (UnsupportedEncodingException ex) {
                setEnabled(false);
                throw new InitializationException("Unexpected mix_audit encoding when reading error stream.", ex);
            } catch (IOException ex) {
                setEnabled(false);
                throw new InitializationException("Unable to read mix_audit output from error stream.", ex);
            }
        } else {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                if (!reader.ready()) {
                    LOGGER.warn("mix_audit input stream unexpectedly not ready to capture version details. Disabling {}", ANALYZER_NAME);
                    setEnabled(false);
                    throw new InitializationException("mix_audit input stream unexpectedly not ready to capture version details.");
                } else {
                    mixAuditVersionDetails = reader.readLine();
                }
            } catch (UnsupportedEncodingException ex) {
                setEnabled(false);
                throw new InitializationException("Unexpected mix_audit encoding when reading input stream.", ex);
            } catch (IOException ex) {
                setEnabled(false);
                throw new InitializationException("Unable to read mix_audit output from input stream.", ex);
            }
        }

        if (isEnabled()) {
            LOGGER.info("{} is enabled and is using mix_audit with version: {}.", ANALYZER_NAME, mixAuditVersionDetails);
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
     * @param folder       directory that contains the mix.lock file
     * @param mixAuditArgs the arguments to pass to mix audit
     * @return a handle to the process
     * @throws AnalysisException thrown when there is an issue launching mix audit
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
            Path homePath = Paths.get(System.getProperty("user.home"));
            Path escriptPath = Paths.get(homePath.toString(), ".mix", "escripts", "mix_audit");
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
     * @param engine     the dependency-check engine
     * @throws AnalysisException thrown if there is an analysis exception.
     */
    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine)
            throws AnalysisException {
        final File parentFile = dependency.getActualFile().getParentFile();
        final List<String> mixAuditArgs = ImmutableList.of("--format", "json");

        final Process process = launchMixAudit(parentFile, mixAuditArgs);
        final int exitValue;
        try {
            exitValue = process.waitFor();
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new AnalysisException("mix_audit process interrupted", ie);
        }
        if (exitValue < 0 || exitValue > 1) {
            final String msg = String.format("Unexpected exit code from mix_audit process; exit code: %s", exitValue);
            throw new AnalysisException(msg);
        }
        try {
            try (BufferedReader errReader = new BufferedReader(new InputStreamReader(process.getErrorStream(), StandardCharsets.UTF_8))) {
                while (errReader.ready()) {
                    final String error = errReader.readLine();
                    LOGGER.warn(error);
                }
            }
            try (BufferedReader rdr = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                processMixAuditOutput(dependency, engine, rdr);
            }
        } catch (IOException | CpeValidationException ioe) {
            LOGGER.warn("mix_audit failure", ioe);
        }
    }

    /**
     * Processes the mix audit output.
     *
     * @param original the dependency
     * @param engine   the dependency-check engine
     * @param rdr      the reader of the report
     * @throws IOException            thrown if the report cannot be read
     * @throws CpeValidationException if there is an error building the
     *                                CPE/VulnerableSoftware object
     */
    private void processMixAuditOutput(Dependency original, Engine engine, BufferedReader rdr) throws AnalysisException, CpeValidationException {
        final MixAuditJsonParser parser = new MixAuditJsonParser(rdr);
        parser.process();

        for (MixAuditResult result : parser.getResults()) {
            Dependency dependency = createDependency(original, result.getDependencyPackage(), result.getDependencyVersion());
            Vulnerability vulnerability = cvedb.getVulnerability(result.getCve());

            if(vulnerability == null) {
                vulnerability = createVulnerability(result);
            }

            dependency.addVulnerability(vulnerability);
            engine.addDependency(dependency);
        }
    }

    private Dependency createDependency(Dependency parentDependency, String packageName, String version) {
        final Dependency dep = new Dependency(parentDependency.getActualFile(), true);

        String identifier = String.format("%s:%s", packageName, version);

        dep.setEcosystem(DEPENDENCY_ECOSYSTEM);
        dep.setDisplayFileName(identifier);
        dep.setName(packageName);
        dep.setVersion(version);
        dep.setPackagePath(identifier);
        dep.setMd5sum(Checksum.getMD5Checksum(identifier));
        dep.setSha1sum(Checksum.getSHA1Checksum(identifier));
        dep.setSha256sum(Checksum.getSHA256Checksum(identifier));

        dep.addEvidence(EvidenceType.VERSION, "mix_audit", "Version", version, Confidence.HIGHEST);
        dep.addEvidence(EvidenceType.PRODUCT, "mix_audit", "Package", packageName, Confidence.HIGHEST);

        try {
            final PackageURL purl = PackageURLBuilder.aPackageURL().withType("hex").withName(packageName)
                    .withVersion(version).build();
            dep.addSoftwareIdentifier(new PurlIdentifier(purl, Confidence.HIGHEST));
        } catch (MalformedPackageURLException ex) {
            LOGGER.debug("Unable to build package url for hex", ex);
            final GenericIdentifier id = new GenericIdentifier("hex:" + packageName + "@" + version,
                    Confidence.HIGHEST);
            dep.addSoftwareIdentifier(id);
        }

        return dep;
    }

    private Vulnerability createVulnerability(MixAuditResult result) throws CpeValidationException {
        final String product = result.getDependencyPackage();
        final String version = result.getDependencyVersion();

        final Vulnerability vulnerability = new Vulnerability();
        vulnerability.setSource(Vulnerability.Source.MIXAUDIT);

        final VulnerableSoftwareBuilder builder = new VulnerableSoftwareBuilder();
        final VulnerableSoftware vs = builder.part(Part.APPLICATION)
                .vendor(String.format("%s_project", product))
                .product(product)
                .version(version).build();

        vulnerability.addVulnerableSoftware(vs);
        vulnerability.setMatchedVulnerableSoftware(vs);

        vulnerability.setCvssV2(new CvssV2(-1, "-", "-", "-", "-", "-", "-", "unknown"));
        vulnerability.setDescription(result.getDescription());
        vulnerability.setName(result.getCve());

        return vulnerability;
    }
}
