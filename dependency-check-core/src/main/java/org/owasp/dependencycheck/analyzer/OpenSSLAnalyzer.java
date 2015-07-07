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

import org.apache.commons.io.filefilter.NameFileFilter;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileFilter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Used to analyze OpenSSL source code present in the file system.
 *
 * @author Dale Visser <dvisser@ida.org>
 */
public class OpenSSLAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * Used when compiling file scanning regex patterns.
     */
    private static final int REGEX_OPTIONS = Pattern.DOTALL
            | Pattern.CASE_INSENSITIVE;

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory
            .getLogger(OpenSSLAnalyzer.class);

    /**
     * Filename extensions for files to be analyzed.
     */
    private static final Set<String> EXTENSIONS = Collections
            .unmodifiableSet(Collections.singleton("h"));

    /**
     * Filter that detects files named "__init__.py".
     */
    private static final FileFilter OPENSSLV_FILTER = new NameFileFilter("opensslv.h");

    private static final int MAJOR_OFFSET = 28;
    private static final long MINOR_MASK = 0x0ff00000L;
    private static final int MINOR_OFFSET = 20;
    private static final long FIX_MASK = 0x000ff000L;
    private static final int FIX_OFFSET = 12;
    private static final long PATCH_MASK = 0x00000ff0L;
    private static final int PATCH_OFFSET = 4;
    private static final int NUM_LETTERS = 26;
    private static final int STATUS_MASK = 0x0000000f;

    static String getOpenSSLVersion(long openSSLVersionConstant) {
        long major = openSSLVersionConstant >>> MAJOR_OFFSET;
        long minor = (openSSLVersionConstant & MINOR_MASK) >>> MINOR_OFFSET;
        long fix = (openSSLVersionConstant & FIX_MASK) >>> FIX_OFFSET;
        long patchLevel = (openSSLVersionConstant & PATCH_MASK) >>> PATCH_OFFSET;
        String patch = 0 == patchLevel || patchLevel > NUM_LETTERS ? "" :
                String.valueOf((char) (patchLevel + 'a' - 1));
        int statusCode = (int) (openSSLVersionConstant & STATUS_MASK);
        String status = 0xf == statusCode ? "" :
                (0 == statusCode ? "-dev" : "-beta" + statusCode);
        return String.format("%d.%d.%d%s%s", major, minor, fix, patch, status);
    }

    /**
     * Returns the name of the Python Package Analyzer.
     *
     * @return the name of the analyzer
     */
    @Override
    public String getName() {
        return "OpenSSL Source Analyzer";
    }

    /**
     * Tell that we are used for information collection.
     *
     * @return INFORMATION_COLLECTION
     */
    @Override
    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.INFORMATION_COLLECTION;
    }

    /**
     * Returns the set of supported file extensions.
     *
     * @return the set of supported file extensions
     */
    @Override
    protected Set<String> getSupportedExtensions() {
        return EXTENSIONS;
    }

    /**
     * No-op initializer implementation.
     *
     * @throws Exception never thrown
     */
    @Override
    protected void initializeFileTypeAnalyzer() throws Exception {
        // Nothing to do here.
    }

    /**
     * Analyzes python packages and adds evidence to the dependency.
     *
     * @param dependency the dependency being analyzed
     * @param engine     the engine being used to perform the scan
     * @throws AnalysisException thrown if there is an unrecoverable error analyzing the dependency
     */
    @Override
    protected void analyzeFileType(Dependency dependency, Engine engine)
            throws AnalysisException {
        final File file = dependency.getActualFile();
        final File parent = file.getParentFile();
        final String parentName = parent.getName();
        boolean found = false;
//        if (INIT_PY_FILTER.accept(file)) {
//            for (final File sourcefile : parent.listFiles(PY_FILTER)) {
//                found |= analyzeFileContents(dependency, sourcefile);
//            }
//        }
        if (found) {
            dependency.setDisplayFileName(parentName + "/__init__.py");
            dependency.getProductEvidence().addEvidence(file.getName(),
                    "PackageName", parentName, Confidence.MEDIUM);
        } else {
            // copy, alter and set in case some other thread is iterating over
            final List<Dependency> deps = new ArrayList<Dependency>(
                    engine.getDependencies());
            deps.remove(dependency);
            engine.setDependencies(deps);
        }
    }

    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return "fixme";
    }
}