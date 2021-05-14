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
 * Copyright (c) 2021 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;
import org.apache.commons.io.FileUtils;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import javax.annotation.concurrent.ThreadSafe;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.Checksum;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.nio.charset.Charset;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import static java.util.stream.Collectors.toCollection;
import org.owasp.dependencycheck.dependency.naming.GenericIdentifier;
import org.owasp.dependencycheck.dependency.naming.Identifier;

/**
 * <p>
 * Used to analyze Perl CPAN files. The analyzer does not yet differentiate
 * developer and test dependencies from required dependencies. Nor does the
 * analyzer support `cpanfile.snapshot` files yet. Finally, version ranges are
 * not yet correctly handled either.</p>
 * <p>
 * Future enhancements should include supporting the snapshot files (which
 * should not have version ranges) and correctly parsing the cpanfile DSL so
 * that one can differentiate developer and test dependencies - which one may
 * not want to include in the analysis.</p>
 *
 * @author Harjit Sandhu
 * @author Jeremy Long
 */
@ThreadSafe
@Experimental
public class PerlCpanfileAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(PerlCpanfileAnalyzer.class);
    /**
     * The filter used to identify CPAN files.
     */
    private static final FileFilter PACKAGE_FILTER = FileFilterBuilder.newInstance().addFilenames("cpanfile").build();
    /**
     * The pattern to extract version numbers from CPAN files.
     */
    private static final Pattern VERSION_PATTERN = Pattern.compile("([0-9\\.]+)");

    /**
     * Create a new Perl CPAN File Analyzer.
     */
    public PerlCpanfileAnalyzer() {
        //empty constructor
    }

    @Override
    protected FileFilter getFileFilter() {
        return PACKAGE_FILTER;
    }

    @Override
    public String getName() {
        return "Perl cpanfile Analyzer";
    }

    @Override
    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.INFORMATION_COLLECTION;
    }

    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_CPANFILE_ENABLED;
    }

    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        //nothing to prepare
    }

    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        engine.removeDependency(dependency);
        final String contents = tryReadFile(dependency.getActualFile());
        final List<String> requires = prepareContents(contents);
        if (requires != null && !requires.isEmpty()) {
            processFileContents(requires, dependency.getFilePath(), engine);
        }
    }

    private String tryReadFile(File file) throws AnalysisException {
        try {
            return FileUtils.readFileToString(file, Charset.defaultCharset()).trim();
        } catch (IOException e) {
            throw new AnalysisException("Problem occurred while reading dependency file.", e);
        }
    }

    protected List<String> prepareContents(String contents) {
        final Pattern pattern = Pattern.compile(";");
        return Arrays.stream(contents.split("\n"))
                .map(r -> r.indexOf("#") > 0 ? r.substring(0, r.indexOf("#")) : r)
                .flatMap(r -> pattern.splitAsStream(r))
                .map(r -> r.trim())
                .filter(r -> r.startsWith("requires"))
                .collect(toCollection(ArrayList::new));
    }

    protected void processFileContents(List<String> fileLines, String filePath, Engine engine) throws AnalysisException {
        fileLines.stream()
                .map(fileLine -> fileLine.split("(,|=>)"))
                .map(requires -> {
                    //LOGGER.debug("perl scanning file:" + fileLine);
                    final String fqName = requires[0].substring(8)
                            .replace("'", "")
                            .replace("\"", "")
                            .trim();
                    final String version;
                    if (requires.length == 1) {
                        version = "0";
                    } else {
                        final Matcher matcher = VERSION_PATTERN.matcher(requires[1]);
                        if (matcher.find()) {
                            version = matcher.group(1);
                        } else {
                            version = "0";
                        }
                    }
                    final int pos = fqName.lastIndexOf("::");
                    final String namespace;
                    final String name;
                    if (pos > 0) {
                        namespace = fqName.substring(0, pos);
                        name = fqName.substring(pos + 2);
                    } else {
                        namespace = null;
                        name = fqName;
                    }
                    final Dependency dependency = new Dependency(true);
                    final File f = new File(filePath);
                    dependency.setFileName(f.getName());
                    dependency.setFilePath(filePath);
                    dependency.setActualFilePath(filePath);
                    dependency.setDisplayFileName("'" + fqName + "', '" + version + "'");
                    dependency.setEcosystem(Ecosystem.PERL);
                    dependency.addEvidence(EvidenceType.VENDOR, "cpanfile", "requires", fqName, Confidence.HIGHEST);
                    dependency.addEvidence(EvidenceType.PRODUCT, "cpanfile", "requires", fqName, Confidence.HIGHEST);
                    dependency.addEvidence(EvidenceType.VERSION, "cpanfile", "requires", version, Confidence.HIGHEST);
                    Identifier id = null;
                    try {
                        //note - namespace might be null and that's okay.
                        final PackageURL purl = PackageURLBuilder.aPackageURL()
                                .withType("cpan")
                                .withNamespace(namespace)
                                .withName(name)
                                .withVersion(version)
                                .build();
                        id = new PurlIdentifier(purl, Confidence.HIGH);
                    } catch (MalformedPackageURLException ex) {
                        LOGGER.debug("Error building package url for " + fqName + "; using generic identifier instead.", ex);
                        id = new GenericIdentifier("cpan:" + fqName + "::" + version, Confidence.HIGH);
                    }
                    dependency.setVersion(version);
                    dependency.setName(fqName);
                    dependency.addSoftwareIdentifier(id);
                    //sha1sum is used for anchor links in the HtML report
                    dependency.setSha1sum(Checksum.getSHA1Checksum(id.getValue()));
                    return dependency;
                }).forEachOrdered(dependency -> {
            engine.addDependency(dependency);
        });
    }

}
