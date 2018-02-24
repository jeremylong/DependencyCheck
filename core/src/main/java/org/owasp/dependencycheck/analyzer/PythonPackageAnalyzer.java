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

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.NameFileFilter;
import org.apache.commons.io.filefilter.SuffixFileFilter;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.UrlStringUtils;

import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.annotation.concurrent.ThreadSafe;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.InitializationException;

/**
 * Used to analyze a Python package, and collect information that can be used to
 * determine the associated CPE.
 *
 * @author Dale Visser
 */
@Experimental
@ThreadSafe
public class PythonPackageAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String DEPENDENCY_ECOSYSTEM = "Python.Pkg";

    /**
     * Used when compiling file scanning regex patterns.
     */
    private static final int REGEX_OPTIONS = Pattern.DOTALL | Pattern.CASE_INSENSITIVE;

    /**
     * Filename extensions for files to be analyzed.
     */
    private static final String EXTENSIONS = "py";

    /**
     * Pattern for matching the module doc string in a source file.
     */
    private static final Pattern MODULE_DOCSTRING = Pattern.compile("^(['\\\"]{3})(.*?)\\1", REGEX_OPTIONS);

    /**
     * Matches assignments to version variables in Python source code.
     */
    private static final Pattern VERSION_PATTERN = Pattern.compile("\\b(__)?version(__)? *= *(['\"]+)(\\d+\\.\\d+.*?)\\3",
            REGEX_OPTIONS);

    /**
     * Matches assignments to title variables in Python source code.
     */
    private static final Pattern TITLE_PATTERN = compileAssignPattern("title");

    /**
     * Matches assignments to summary variables in Python source code.
     */
    private static final Pattern SUMMARY_PATTERN = compileAssignPattern("summary");

    /**
     * Matches assignments to URL/URL variables in Python source code.
     */
    private static final Pattern URI_PATTERN = compileAssignPattern("ur[il]");

    /**
     * Matches assignments to home page variables in Python source code.
     */
    private static final Pattern HOMEPAGE_PATTERN = compileAssignPattern("home_?page");

    /**
     * Matches assignments to author variables in Python source code.
     */
    private static final Pattern AUTHOR_PATTERN = compileAssignPattern("author");

    /**
     * Filter that detects files named "__init__.py".
     */
    private static final FileFilter INIT_PY_FILTER = new NameFileFilter("__init__.py");

    /**
     * The file filter for python files.
     */
    private static final FileFilter PY_FILTER = new SuffixFileFilter(".py");

    /**
     * The file filter used to determine which files this analyzer supports.
     */
    private static final FileFilter FILTER = FileFilterBuilder.newInstance().addExtensions(EXTENSIONS).build();

    /**
     * Returns the name of the Python Package Analyzer.
     *
     * @return the name of the analyzer
     */
    @Override
    public String getName() {
        return "Python Package Analyzer";
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
     * Returns the key name for the analyzers enabled setting.
     *
     * @return the key name for the analyzers enabled setting
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_PYTHON_PACKAGE_ENABLED;
    }

    /**
     * Returns the FileFilter
     *
     * @return the FileFilter
     */
    @Override
    protected FileFilter getFileFilter() {
        return FILTER;
    }

    /**
     * No-op initializer implementation.
     *
     * @param engine a reference to the dependency-check engine
     * @throws InitializationException never thrown
     */
    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        // Nothing to do here.
    }

    /**
     * Utility function to create a regex pattern matcher.
     *
     * @param name the value to use when constructing the assignment pattern
     * @return the compiled Pattern
     */
    private static Pattern compileAssignPattern(String name) {
        return Pattern.compile(
                String.format("\\b(__)?%s(__)?\\b *= *(['\"]+)(.*?)\\3", name),
                REGEX_OPTIONS);
    }

    /**
     * Analyzes python packages and adds evidence to the dependency.
     *
     * @param dependency the dependency being analyzed
     * @param engine the engine being used to perform the scan
     * @throws AnalysisException thrown if there is an unrecoverable error
     * analyzing the dependency
     */
    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine)
            throws AnalysisException {
        dependency.setEcosystem(DEPENDENCY_ECOSYSTEM);
        final File file = dependency.getActualFile();
        final File parent = file.getParentFile();
        final String parentName = parent.getName();
        if (INIT_PY_FILTER.accept(file)) {
            //by definition, the containing folder of __init__.py is considered the package, even the file is empty:
            //"The __init__.py files are required to make Python treat the directories as containing packages"
            //see section "6.4 Packages" from https://docs.python.org/2/tutorial/modules.html;
            dependency.addEvidence(EvidenceType.PRODUCT, file.getName(), "PackageName", parentName, Confidence.HIGHEST);
            dependency.setName(parentName);

            final File[] fileList = parent.listFiles(PY_FILTER);
            if (fileList != null) {
                for (final File sourceFile : fileList) {
                    analyzeFileContents(dependency, sourceFile);
                }
            }
        } else {
            engine.removeDependency(dependency);
        }
    }

    /**
     * This should gather information from leading docstrings, file comments,
     * and assignments to __version__, __title__, __summary__, __uri__, __url__,
     * __home*page__, __author__, and their all caps equivalents.
     *
     * @param dependency the dependency being analyzed
     * @param file the file name to analyze
     * @return whether evidence was found
     * @throws AnalysisException thrown if there is an unrecoverable error
     */
    private boolean analyzeFileContents(Dependency dependency, File file)
            throws AnalysisException {
        final String contents;
        try {
            contents = FileUtils.readFileToString(file, Charset.defaultCharset()).trim();
        } catch (IOException e) {
            throw new AnalysisException("Problem occurred while reading dependency file.", e);
        }
        boolean found = false;
        if (!contents.isEmpty()) {
            final String source = file.getName();
            found = gatherEvidence(dependency, EvidenceType.VERSION, VERSION_PATTERN, contents,
                    source, "SourceVersion", Confidence.MEDIUM);
            found |= addSummaryInfo(dependency, SUMMARY_PATTERN, 4, contents,
                    source, "summary");
            if (INIT_PY_FILTER.accept(file)) {
                found |= addSummaryInfo(dependency, MODULE_DOCSTRING, 2,
                        contents, source, "docstring");
            }
            found |= gatherEvidence(dependency, EvidenceType.PRODUCT, TITLE_PATTERN, contents,
                    source, "SourceTitle", Confidence.LOW);

            found |= gatherEvidence(dependency, EvidenceType.VENDOR, AUTHOR_PATTERN, contents,
                    source, "SourceAuthor", Confidence.MEDIUM);
            found |= gatherHomePageEvidence(dependency, EvidenceType.VENDOR, URI_PATTERN,
                    source, "URL", contents);
            found |= gatherHomePageEvidence(dependency, EvidenceType.VENDOR, HOMEPAGE_PATTERN,
                    source, "HomePage", contents);
        }
        return found;
    }

    /**
     * Adds summary information to the dependency
     *
     * @param dependency the dependency being analyzed
     * @param pattern the pattern used to perform analysis
     * @param group the group from the pattern that indicates the data to use
     * @param contents the data being analyzed
     * @param source the source name to use when recording the evidence
     * @param key the key name to use when recording the evidence
     * @return true if evidence was collected; otherwise false
     */
    private boolean addSummaryInfo(Dependency dependency, Pattern pattern,
            int group, String contents, String source, String key) {
        final Matcher matcher = pattern.matcher(contents);
        final boolean found = matcher.find();
        if (found) {
            JarAnalyzer.addDescription(dependency, matcher.group(group),
                    source, key);
        }
        return found;
    }

    /**
     * Collects evidence from the home page URL.
     *
     * @param dependency the dependency that is being analyzed
     * @param type the type of evidence
     * @param pattern the pattern to match
     * @param source the source of the evidence
     * @param name the name of the evidence
     * @param contents the home page URL
     * @return true if evidence was collected; otherwise false
     */
    private boolean gatherHomePageEvidence(Dependency dependency, EvidenceType type, Pattern pattern,
            String source, String name, String contents) {
        final Matcher matcher = pattern.matcher(contents);
        boolean found = false;
        if (matcher.find()) {
            final String url = matcher.group(4);
            if (UrlStringUtils.isUrl(url)) {
                found = true;
                dependency.addEvidence(type, source, name, url, Confidence.MEDIUM);
            }
        }
        return found;
    }

    /**
     * Gather evidence from a Python source file using the given string
     * assignment regex pattern.
     *
     * @param dependency the dependency that is being analyzed
     * @param type the type of evidence
     * @param pattern to scan contents with
     * @param contents of Python source file
     * @param source for storing evidence
     * @param name of evidence
     * @param confidence in evidence
     * @return whether evidence was found
     */
    private boolean gatherEvidence(Dependency dependency, EvidenceType type, Pattern pattern, String contents,
            String source, String name, Confidence confidence) {
        final Matcher matcher = pattern.matcher(contents);
        final boolean found = matcher.find();
        if (found) {
            dependency.addEvidence(type, source, name, matcher.group(4), confidence);
            if (type == EvidenceType.VERSION) {
                dependency.setVersion(matcher.group(4));
            }
        }
        return found;
    }
}
