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
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import javax.annotation.concurrent.ThreadSafe;
import javax.json.Json;
import javax.json.JsonException;
import javax.json.JsonObject;
import javax.json.JsonString;
import javax.json.JsonReader;
import javax.json.JsonValue;
import org.owasp.dependencycheck.Engine.Mode;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.Checksum;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.ICveDBWrapper;
import org.owasp.dependencycheck.data.nvdcve.CveDBWrapper;
import org.owasp.dependencycheck.models.VulnerabilityDTO;

import java.sql.ResultSet;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.nio.charset.Charset;

import java.util.ArrayList;
import java.util.List;

/**
 * Used to analyze perl cpan files
 *
 * @author Harjit Sandhu
 */
@ThreadSafe
public class PerlCpanfileAnalyzer extends AbstractFileTypeAnalyzer {

    private static final Logger LOGGER = LoggerFactory.getLogger(PerlCpanfileAnalyzer.class);
    private static final FileFilter PACKAGE_FILTER = FileFilterBuilder.newInstance().addFilenames("cpanfile").build();
    private static final int REGEX_OPTIONS = Pattern.DOTALL | Pattern.CASE_INSENSITIVE;
    private static final Pattern DEPEND_PERL_CPAN_PATTERN = Pattern.compile("requires '(.*?)'.*?([0-9\\.]+).*", REGEX_OPTIONS);
    private static List<VulnerabilityDTO> vulnerabileProductList;
    private static ICveDBWrapper cveDatabase;

    public PerlCpanfileAnalyzer(){
    }

    public PerlCpanfileAnalyzer(List<VulnerabilityDTO> _vulnerabileProductList, ICveDBWrapper _cveDatabase){
        vulnerabileProductList = _vulnerabileProductList;
        cveDatabase = _cveDatabase;
    }

    @Override
    protected FileFilter getFileFilter() {
        return PACKAGE_FILTER;
    }

    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        engine.openDatabase();
        cveDatabase = new CveDBWrapper(engine.getDatabase());
        vulnerabileProductList = cveDatabase.getPerlVulnerabilities();
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
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        final File file = dependency.getActualFile();
        final File parent = file.getParentFile();
        final File[] fileList = parent.listFiles(this.getFileFilter());
        if (fileList != null) {
            for (final File sourceFile : fileList) {
                analyzeFileContents(dependency, sourceFile);
            }
        }
    }

    private void analyzeFileContents(Dependency dependency, File file) throws AnalysisException {
        final String contents = tryReadFile(file);
        if (!contents.isEmpty()) {
            processFileContents(contents.split(";"), dependency);
        }
    }

    private String tryReadFile(File file) throws AnalysisException {
        try {
            return FileUtils.readFileToString(file, Charset.defaultCharset()).trim();
        } catch (IOException e) {
            throw new AnalysisException("Problem occurred while reading dependency file.", e);
        }
    }

    protected void processFileContents(String[] fileLines, Dependency dependency) throws AnalysisException{
        final List<Vulnerability> vulns = new ArrayList<>();
        for(String fileLine:fileLines){  
            Matcher matcher = DEPEND_PERL_CPAN_PATTERN.matcher(fileLine);
            if (matcher == null){
                System.out.println("Perl regex match was null:" + fileLine);
                LOGGER.debug("Perl regex match was null:" + fileLine);
            }
            LOGGER.debug("perl scanning file:" + fileLine);
            while(matcher.find()) {
                int matcherGroupCount = matcher.groupCount();
                if (matcherGroupCount >= 2){
                    String dependencyName = matcher.group(1);
                    String dependencyVersion = matcher.group(2);
                    String productName = dependencyName.split(":")[0];
                    LOGGER.debug("Name:" + dependencyName + " - Version:" + dependencyVersion);
                    dependency.addEvidence(EvidenceType.PRODUCT, dependencyName, productName, dependencyVersion, Confidence.HIGHEST);                
                    for(VulnerabilityDTO vp : vulnerabileProductList){
                        if(vp.hasMatch(productName)){
                            final Vulnerability individualVuln = cveDatabase.getVulnerability(vp.getCveReference());
                            vulns.add(individualVuln);
                        }
                    }
                }else{
                    LOGGER.debug("Matcher didn't find have the correct number of groups : " + matcherGroupCount + ", in :" + fileLine);
                }
            }
        }
        dependency.addVulnerabilities(vulns);
    }
}
