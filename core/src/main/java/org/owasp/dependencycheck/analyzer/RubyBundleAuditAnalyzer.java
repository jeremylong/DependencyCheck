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
 * Copyright (c) 2015 Institute for Defense Analyses. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;
import com.google.common.collect.ImmutableList;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.concurrent.ThreadSafe;

import org.apache.commons.io.FileUtils;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.CvssV2;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.dependency.Reference;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.dependency.VulnerableSoftwareBuilder;
import org.owasp.dependencycheck.dependency.naming.GenericIdentifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import us.springett.parsers.cpe.exceptions.CpeValidationException;
import us.springett.parsers.cpe.values.Part;

/**
 * Used to analyze Ruby Bundler Gemspec.lock files utilizing the 3rd party
 * bundle-audit tool.
 *
 * @author Dale Visser
 */
@ThreadSafe
public class RubyBundleAuditAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(RubyBundleAuditAnalyzer.class);

    /**
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String DEPENDENCY_ECOSYSTEM = "ruby";

    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Ruby Bundle Audit Analyzer";

    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.PRE_INFORMATION_COLLECTION;
    /**
     * The filter defining which files will be analyzed.
     */
    private static final FileFilter FILTER = FileFilterBuilder.newInstance().addFilenames("Gemfile.lock").build();
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
     * If {@link #analyzeDependency(Dependency, Engine)} is called, then we have
     * successfully initialized, and it will be necessary to disable
     * {@link RubyGemspecAnalyzer}.
     */
    private boolean needToDisableGemspecAnalyzer = true;

    /**
     * @return a filter that accepts files named Gemfile.lock
     */
    @Override
    protected FileFilter getFileFilter() {
        return FILTER;
    }

    /**
     * Launch bundle-audit.
     *
     * @param folder directory that contains bundle audit
     * @param bundleAuditArgs the arguments to pass to bundle audit
     * @return a handle to the process
     * @throws AnalysisException thrown when there is an issue launching bundle
     * audit
     */
    private Process launchBundleAudit(File folder, List<String> bundleAuditArgs) throws AnalysisException {
        if (!folder.isDirectory()) {
            throw new AnalysisException(String.format("%s should have been a directory.", folder.getAbsolutePath()));
        }
        final List<String> args = new ArrayList<>();
        final String bundleAuditPath = getSettings().getString(Settings.KEYS.ANALYZER_BUNDLE_AUDIT_PATH);
        File bundleAudit = null;
        if (bundleAuditPath != null) {
            bundleAudit = new File(bundleAuditPath);
            if (!bundleAudit.isFile()) {
                LOGGER.warn("Supplied `bundleAudit` path is incorrect: {}", bundleAuditPath);
                bundleAudit = null;
            }
        }
        args.add(bundleAudit != null ? bundleAudit.getAbsolutePath() : "bundle-audit");
        args.addAll(bundleAuditArgs);
        final ProcessBuilder builder = new ProcessBuilder(args);

        final String bundleAuditWorkingDirectoryPath = getSettings().getString(Settings.KEYS.ANALYZER_BUNDLE_AUDIT_WORKING_DIRECTORY);
        File bundleAuditWorkingDirectory = null;
        if (bundleAuditWorkingDirectoryPath != null) {
            bundleAuditWorkingDirectory = new File(bundleAuditWorkingDirectoryPath);
            if (!bundleAuditWorkingDirectory.isDirectory()) {
                LOGGER.warn("Supplied `bundleAuditWorkingDirectory` path is incorrect: {}", bundleAuditWorkingDirectoryPath);
                bundleAuditWorkingDirectory = null;
            }
        }
        final File launchBundleAuditFromDirectory = bundleAuditWorkingDirectory != null ? bundleAuditWorkingDirectory : folder;
        builder.directory(launchBundleAuditFromDirectory);
        try {
            LOGGER.info("Launching: {} from {}", args, launchBundleAuditFromDirectory);
            return builder.start();
        } catch (IOException ioe) {
            throw new AnalysisException("bundle-audit initialization failure; this error can be ignored if you are not analyzing Ruby. "
                    + "Otherwise ensure that bundle-audit is installed and the path to bundle audit is correctly specified", ioe);
        }
    }

    /**
     * Initialize the analyzer.
     *
     * @param engine a reference to the dependency-check engine
     * @throws InitializationException if anything goes wrong
     */
    @Override
    public void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        if (engine != null) {
            this.cvedb = engine.getDatabase();
        }

        // Here we check if bundle-audit actually runs from this location. We do this by running the
        // `bundle-audit version` command and seeing whether or not it succeeds (if it returns with an exit value of 0)
        final Process process;
        try {
            List<String> bundleAuditArgs = ImmutableList.of("version");
            process = launchBundleAudit(getSettings().getTempDirectory(), bundleAuditArgs);
        } catch (AnalysisException ae) {
            setEnabled(false);
            final String msg = String.format("Exception from bundle-audit process: %s. Disabling %s", ae.getCause(), ANALYZER_NAME);
            throw new InitializationException(msg, ae);
        } catch (IOException ex) {
            setEnabled(false);
            throw new InitializationException("Unable to create temporary file, the Ruby Bundle Audit Analyzer will be disabled", ex);
        }

        final int exitValue;
        try {
            exitValue = process.waitFor();
        } catch (InterruptedException ex) {
            setEnabled(false);
            final String msg = String.format("Bundle-audit process was interrupted. Disabling %s", ANALYZER_NAME);
            Thread.currentThread().interrupt();
            throw new InitializationException(msg);
        }

        final String bundleAuditVersionDetails;
        if (exitValue != 0) {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getErrorStream(), StandardCharsets.UTF_8))) {
                if (!reader.ready()) {
                    LOGGER.warn("Unexpected exit value from bundle-audit process and error stream unexpectedly not ready to capture error details. "
                            + "Disabling {}. Exit value was: {}", ANALYZER_NAME, exitValue);
                    setEnabled(false);
                    throw new InitializationException("Bundle-audit error stream unexpectedly not ready.");
                } else {
                    final String line = reader.readLine();
                    setEnabled(false);
                    LOGGER.warn("Unexpected exit value from bundle-audit process. Disabling {}. Exit value was: {}. error stream output from bundle-audit "
                            + "process was: {}", ANALYZER_NAME, exitValue, line);
                    throw new InitializationException("Unexpected exit value from bundle-audit process.");
                }
            } catch (UnsupportedEncodingException ex) {
                setEnabled(false);
                throw new InitializationException("Unexpected bundle-audit encoding when reading error stream.", ex);
            } catch (IOException ex) {
                setEnabled(false);
                throw new InitializationException("Unable to read bundle-audit output from error stream.", ex);
            }
        } else {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                if (!reader.ready()) {
                    LOGGER.warn("Bundle-audit input stream unexpectedly not ready to capture version details. Disabling {}", ANALYZER_NAME);
                    setEnabled(false);
                    throw new InitializationException("Bundle-audit input stream unexpectedly not ready to capture version details.");
                } else {
                    bundleAuditVersionDetails = reader.readLine();
                }
            } catch (UnsupportedEncodingException ex) {
                setEnabled(false);
                throw new InitializationException("Unexpected bundle-audit encoding when reading input stream.", ex);
            } catch (IOException ex) {
                setEnabled(false);
                throw new InitializationException("Unable to read bundle-audit output from input stream.", ex);
            }
        }

        if (isEnabled()) {
            LOGGER.info("{} is enabled and is using bundle-audit with version details: {}. Note: It is necessary to manually run "
                    + "\"bundle-audit update\" occasionally to keep its database up to date.", ANALYZER_NAME, bundleAuditVersionDetails);
        }
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
     * Returns the key used in the properties file to reference the analyzer's
     * enabled property.
     *
     * @return the analyzer's enabled property setting key
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_BUNDLE_AUDIT_ENABLED;
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
        if (needToDisableGemspecAnalyzer) {
            boolean failed = true;
            final String className = RubyGemspecAnalyzer.class.getName();
            for (FileTypeAnalyzer analyzer : engine.getFileTypeAnalyzers()) {
                if (analyzer instanceof RubyBundlerAnalyzer) {
                    ((RubyBundlerAnalyzer) analyzer).setEnabled(false);
                    LOGGER.info("Disabled {} to avoid noisy duplicate results.", RubyBundlerAnalyzer.class.getName());
                } else if (analyzer instanceof RubyGemspecAnalyzer) {
                    ((RubyGemspecAnalyzer) analyzer).setEnabled(false);
                    LOGGER.info("Disabled {} to avoid noisy duplicate results.", className);
                    failed = false;
                }
            }
            if (failed) {
                LOGGER.warn("Did not find {}.", className);
            }
            needToDisableGemspecAnalyzer = false;
        }
        final File parentFile = dependency.getActualFile().getParentFile();
        final List<String> bundleAuditArgs = ImmutableList.of("check", "--verbose");

        final Process process = launchBundleAudit(parentFile, bundleAuditArgs);
        final int exitValue;
        try {
            exitValue = process.waitFor();
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new AnalysisException("bundle-audit process interrupted", ie);
        }
        if (exitValue < 0 || exitValue > 1) {
            final String msg = String.format("Unexpected exit code from bundle-audit process; exit code: %s", exitValue);
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
                processBundlerAuditOutput(dependency, engine, rdr);
            }
        } catch (IOException | CpeValidationException ioe) {
            LOGGER.warn("bundle-audit failure", ioe);
        }
    }

    /**
     * Processes the bundler audit output.
     *
     * @param original the dependency
     * @param engine the dependency-check engine
     * @param rdr the reader of the report
     * @throws IOException thrown if the report cannot be read
     * @throws CpeValidationException if there is an error building the
     * CPE/VulnerableSoftware object
     */
    private void processBundlerAuditOutput(Dependency original, Engine engine, BufferedReader rdr) throws IOException, CpeValidationException {
        final String parentName = original.getActualFile().getParentFile().getName();
        final String fileName = original.getFileName();
        final String filePath = original.getFilePath();
        Dependency dependency = null;
        Vulnerability vulnerability = null;
        String gem = null;
        final Map<String, Dependency> map = new HashMap<>();
        boolean appendToDescription = false;
        while (rdr.ready()) {
            final String nextLine = rdr.readLine();
            if (null == nextLine) {
                break;
            } else if (nextLine.startsWith(NAME)) {
                appendToDescription = false;
                gem = nextLine.substring(NAME.length());
                if (!map.containsKey(gem)) {
                    map.put(gem, createDependencyForGem(engine, parentName, fileName, filePath, gem));
                }
                dependency = map.get(gem);
                LOGGER.debug("bundle-audit ({}): {}", parentName, nextLine);
            } else if (nextLine.startsWith(VERSION)) {
                vulnerability = createVulnerability(parentName, dependency, gem, nextLine);
            } else if (nextLine.startsWith(ADVISORY)) {
                setVulnerabilityName(parentName, dependency, vulnerability, nextLine);
            } else if (nextLine.startsWith(CRITICALITY)) {
                addCriticalityToVulnerability(parentName, vulnerability, nextLine);
            } else if (nextLine.startsWith("URL: ")) {
                addReferenceToVulnerability(parentName, vulnerability, nextLine);
            } else if (nextLine.startsWith("Description:")) {
                appendToDescription = true;
                if (null != vulnerability) {
                    vulnerability.setDescription("*** Vulnerability obtained from bundle-audit verbose report. "
                            + "Title link may not work. CPE below is guessed. CVSS score is estimated (-1.0 "
                            + " indicates unknown). See link below for full details. *** ");
                }
            } else if (appendToDescription && null != vulnerability) {
                vulnerability.setDescription(vulnerability.getDescription() + nextLine + "\n");
            }
        }
    }

    /**
     * Sets the vulnerability name.
     *
     * @param parentName the parent name
     * @param dependency the dependency
     * @param vulnerability the vulnerability
     * @param nextLine the line to parse
     */
    private void setVulnerabilityName(String parentName, Dependency dependency, Vulnerability vulnerability, String nextLine) {
        final String advisory = nextLine.substring(ADVISORY.length());
        if (null != vulnerability) {
            vulnerability.setName(advisory);
        }
        if (null != dependency) {
            dependency.addVulnerability(vulnerability);
        }
        LOGGER.debug("bundle-audit ({}): {}", parentName, nextLine);
    }

    /**
     * Adds a reference to the vulnerability.
     *
     * @param parentName the parent name
     * @param vulnerability the vulnerability
     * @param nextLine the line to parse
     */
    private void addReferenceToVulnerability(String parentName, Vulnerability vulnerability, String nextLine) {
        final String url = nextLine.substring("URL: ".length());
        if (null != vulnerability) {
            final Reference ref = new Reference();
            ref.setName(vulnerability.getName());
            ref.setSource("bundle-audit");
            ref.setUrl(url);
            vulnerability.getReferences().add(ref);
        }
        LOGGER.debug("bundle-audit ({}): {}", parentName, nextLine);
    }

    /**
     * Adds the criticality to the vulnerability
     *
     * @param parentName the parent name
     * @param vulnerability the vulnerability
     * @param nextLine the line to parse
     */
    private void addCriticalityToVulnerability(String parentName, Vulnerability vulnerability, String nextLine) {
        if (null != vulnerability) {
            final String criticality = nextLine.substring(CRITICALITY.length()).trim();
            float score = -1.0f;
            Vulnerability v = null;
            if (cvedb != null) {
                try {
                    v = cvedb.getVulnerability(vulnerability.getName());
                } catch (DatabaseException ex) {
                    LOGGER.debug("Unable to look up vulnerability {}", vulnerability.getName());
                }
            }
            if (v != null && (v.getCvssV2() != null || v.getCvssV3() != null)) {
                if (v.getCvssV2() != null) {
                    vulnerability.setCvssV2(v.getCvssV2());
                }
                if (v.getCvssV3() != null) {
                    vulnerability.setCvssV3(v.getCvssV3());
                }
            } else {
                if ("High".equalsIgnoreCase(criticality)) {
                    score = 8.5f;
                } else if ("Medium".equalsIgnoreCase(criticality)) {
                    score = 5.5f;
                } else if ("Low".equalsIgnoreCase(criticality)) {
                    score = 2.0f;
                }
                vulnerability.setCvssV2(new CvssV2(score, "-", "-", "-", "-", "-", "-", criticality));
            }
        }
        LOGGER.debug("bundle-audit ({}): {}", parentName, nextLine);
    }

    /**
     * Creates a vulnerability.
     *
     * @param parentName the parent name
     * @param dependency the dependency
     * @param gem the gem name
     * @param nextLine the line to parse
     * @return the vulnerability
     * @throws CpeValidationException thrown if there is an error building the
     * CPE vulnerability object
     */
    private Vulnerability createVulnerability(String parentName, Dependency dependency, String gem, String nextLine) throws CpeValidationException {
        Vulnerability vulnerability = null;
        if (null != dependency) {
            final String version = nextLine.substring(VERSION.length());
            dependency.addEvidence(EvidenceType.VERSION,
                    "bundler-audit",
                    "Version",
                    version,
                    Confidence.HIGHEST);
            dependency.setVersion(version);
            dependency.setName(gem);
            try {
                final PackageURL purl = PackageURLBuilder.aPackageURL().withType("gem").withName(dependency.getName())
                        .withVersion(dependency.getVersion()).build();
                dependency.addSoftwareIdentifier(new PurlIdentifier(purl, Confidence.HIGHEST));
            } catch (MalformedPackageURLException ex) {
                LOGGER.debug("Unable to build package url for python", ex);
                final GenericIdentifier id = new GenericIdentifier("gem:" + dependency.getName() + "@" + dependency.getVersion(),
                        Confidence.HIGHEST);
                dependency.addSoftwareIdentifier(id);
            }

            vulnerability = new Vulnerability(); // don't add to dependency until we have name set later
            vulnerability.setSource(Vulnerability.Source.BUNDLEAUDIT);
            final VulnerableSoftwareBuilder builder = new VulnerableSoftwareBuilder();
            final VulnerableSoftware vs = builder.part(Part.APPLICATION)
                    .vendor(gem)
                    .product(String.format("%s_project", gem))
                    .version(version).build();
            vulnerability.addVulnerableSoftware(vs);
            vulnerability.setMatchedVulnerableSoftware(vs);
            vulnerability.setCvssV2(new CvssV2(-1, "-", "-", "-", "-", "-", "-", "unknown"));
        }
        LOGGER.debug("bundle-audit ({}): {}", parentName, nextLine);
        return vulnerability;
    }

    /**
     * Creates the dependency based off of the gem.
     *
     * @param engine the engine used for scanning
     * @param parentName the gem parent
     * @param fileName the file name
     * @param filePath the file path
     * @param gem the gem name
     * @return the dependency to add
     * @throws IOException thrown if a temporary gem file could not be written
     */
    private Dependency createDependencyForGem(Engine engine, String parentName, String fileName, String filePath, String gem) throws IOException {
        final File gemFile;
        try {
            gemFile = File.createTempFile(gem, "_Gemfile.lock", getSettings().getTempDirectory());
        } catch (IOException ioe) {
            throw new IOException("Unable to create temporary gem file");
        }
        final String displayFileName = String.format("%s%c%s:%s", parentName, File.separatorChar, fileName, gem);

        FileUtils.write(gemFile, displayFileName, Charset.defaultCharset()); // unique contents to avoid dependency bundling
        final Dependency dependency = new Dependency(gemFile);
        dependency.setEcosystem(DEPENDENCY_ECOSYSTEM);
        dependency.addEvidence(EvidenceType.PRODUCT, "bundler-audit", "Name", gem, Confidence.HIGHEST);
        //TODO add package URL - note, this may require parsing the gemfile.lock and getting the version for each entry
        dependency.setDisplayFileName(displayFileName);
        dependency.setFileName(fileName);
        dependency.setFilePath(filePath);
        engine.addDependency(dependency);
        return dependency;
    }
}
