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
import org.owasp.dependencycheck.dependency.Vulnerability;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.nio.charset.Charset;

import java.util.ArrayList;
import java.util.List;
import org.owasp.dependencycheck.dependency.naming.GenericIdentifier;
import org.owasp.dependencycheck.dependency.naming.Identifier;

/**
 * <p>
 * Used to analyze perl cpan files. The analyzer does not yet differentiate
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
 */
@ThreadSafe
@Experimental
public class PerlCpanfileAnalyzer extends AbstractFileTypeAnalyzer {

    private static final Logger LOGGER = LoggerFactory.getLogger(PerlCpanfileAnalyzer.class);
    private static final FileFilter PACKAGE_FILTER = FileFilterBuilder.newInstance().addFilenames("cpanfile").build();
    private static final int REGEX_OPTIONS = Pattern.DOTALL | Pattern.CASE_INSENSITIVE;
    private static final Pattern DEPEND_PERL_CPAN_PATTERN = Pattern.compile("requires [\"'](.*?)[\"'].*?([0-9\\.]+).*", REGEX_OPTIONS);

    public PerlCpanfileAnalyzer() {
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
        return Settings.KEYS.ANALYZER_EXPERIMENTAL_ENABLED;
    }

    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        //nothing to prepare
    }

    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        engine.removeDependency(dependency);
        final String contents = tryReadFile(dependency.getActualFile());
        if (!contents.isEmpty()) {
            processFileContents(contents.split(";"), dependency.getFilePath(), engine);
        }
    }

    private String tryReadFile(File file) throws AnalysisException {
        try {
            return FileUtils.readFileToString(file, Charset.defaultCharset()).trim();
        } catch (IOException e) {
            throw new AnalysisException("Problem occurred while reading dependency file.", e);
        }
    }

    protected void processFileContents(String[] fileLines, String filePath, Engine engine) throws AnalysisException {
        for (String fileLine : fileLines) {
            Matcher matcher = DEPEND_PERL_CPAN_PATTERN.matcher(fileLine);
            if (matcher == null) {
                LOGGER.debug("Perl regex match was null:" + fileLine);
            } else {
                LOGGER.debug("perl scanning file:" + fileLine);
                while (matcher.find()) {
                    final int matcherGroupCount = matcher.groupCount();
                    if (matcherGroupCount >= 2) {
                        final String fqName = matcher.group(1);
                        final String version = matcher.group(2);
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

                        Dependency dependency = new Dependency(true);
                        File f = new File(filePath);
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
                        engine.addDependency(dependency);
                    } else {
                        LOGGER.debug("Matcher didn't find have the correct number of groups : " + matcherGroupCount + ", in :" + fileLine);
                    }
                }
            }
        }
    }

}
