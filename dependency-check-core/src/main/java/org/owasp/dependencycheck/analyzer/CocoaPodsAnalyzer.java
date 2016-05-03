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
 * Copyright (c) 2015 Bianca Jiang. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.json.JsonObject;
import javax.json.JsonString;
import javax.json.JsonValue;

import org.apache.commons.io.FileUtils;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceCollection;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Bianca Xue Jiang
 *
 */
public class CocoaPodsAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(CocoaPodsAnalyzer.class);

    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "CocoaPods Package Analyzer";

    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;

    /**
     * The file name to scan.
     */
    public static final String PODSPEC = "podspec";
    /**
     * Filter that detects files named "package.json".
     */
    private static final FileFilter PODSPEC_FILTER = FileFilterBuilder.newInstance().addExtensions(PODSPEC).build();


    /**
     * The capture group #1 is the block variable.  
     * e.g. "Pod::Spec.new do |spec|"
     */
    private static final Pattern PODSPEC_BLOCK_PATTERN
            = Pattern.compile("Pod::Spec\\.new\\s+?do\\s+?\\|(.+?)\\|");
    
    
    /**
     * Returns the FileFilter
     *
     * @return the FileFilter
     */
    @Override
    protected FileFilter getFileFilter() {
        return PODSPEC_FILTER;
    }

    @Override
    protected void initializeFileTypeAnalyzer() throws Exception {
        // NO-OP
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
     * Returns the key used in the properties file to reference the analyzer's enabled property.
     *
     * @return the analyzer's enabled property setting key
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_NODE_PACKAGE_ENABLED;
    }

    @Override
    protected void analyzeFileType(Dependency dependency, Engine engine)
            throws AnalysisException {
    	
    	String contents;
        try {
            contents = FileUtils.readFileToString(dependency.getActualFile(), Charset.defaultCharset());
        } catch (IOException e) {
            throw new AnalysisException(
                    "Problem occurred while reading dependency file.", e);
        }
        final Matcher matcher = PODSPEC_BLOCK_PATTERN.matcher(contents);
        if (matcher.find()) {
            contents = contents.substring(matcher.end());
            final String blockVariable = matcher.group(1);
            
            final EvidenceCollection vendor = dependency.getVendorEvidence();
            final EvidenceCollection product = dependency.getProductEvidence();
            final EvidenceCollection version = dependency.getVersionEvidence();
            
            final String name = addStringEvidence(product, contents, blockVariable, "name", "name", Confidence.HIGHEST);
            if (!name.isEmpty()) {
                vendor.addEvidence(PODSPEC, "name_project", name, Confidence.LOW);
            }
            addStringEvidence(product, contents, blockVariable, "summary", "summary", Confidence.LOW);

            addStringEvidence(vendor, contents, blockVariable, "author", "authors?", Confidence.HIGHEST);
            addStringEvidence(vendor, contents, blockVariable, "homepage", "homepage", Confidence.HIGHEST);
            addStringEvidence(vendor, contents, blockVariable, "license", "licen[cs]es?", Confidence.HIGHEST);
            
            addStringEvidence(version, contents, blockVariable, "version", "version", Confidence.HIGHEST);
        }
        
        setPackagePath(dependency);
    }
    
    private String addStringEvidence(EvidenceCollection evidences, String contents,
            String blockVariable, String field, String fieldPattern, Confidence confidence) {
        String value = "";
        
    	//capture array value between [ ]
    	final Matcher arrayMatcher = Pattern.compile(
                String.format("\\s*?%s\\.%s\\s*?=\\s*?\\{\\s*?(.*?)\\s*?\\}", blockVariable, fieldPattern), Pattern.CASE_INSENSITIVE).matcher(contents);
    	if(arrayMatcher.find()) {
    		value = arrayMatcher.group(1);
    	}
    	//capture single value between quotes
    	else {
	        final Matcher matcher = Pattern.compile(
	                String.format("\\s*?%s\\.%s\\s*?=\\s*?(['\"])(.*?)\\1", blockVariable, fieldPattern), Pattern.CASE_INSENSITIVE).matcher(contents);
	        if (matcher.find()) {
	            value = matcher.group(2);
	        }
    	}
    	if(value.length() > 0)
    		evidences.addEvidence(PODSPEC, field, value, confidence);
    	
        return value;
    }

    private void setPackagePath(Dependency dep) {
    	File file = new File(dep.getFilePath());
    	String parent = file.getParent();
    	if(parent != null)
    		dep.setPackagePath(parent);
    }

    /**
     * Adds information to an evidence collection from the node json configuration.
     *
     * @param json information from node.js
     * @param collection a set of evidence about a dependency
     * @param key the key to obtain the data from the json information
     */
    private void addToEvidence(JsonObject json, EvidenceCollection collection, String key) {
        if (json.containsKey(key)) {
            final JsonValue value = json.get(key);
            if (value instanceof JsonString) {
                collection.addEvidence(PODSPEC, key, ((JsonString) value).getString(), Confidence.HIGHEST);
            } else if (value instanceof JsonObject) {
                final JsonObject jsonObject = (JsonObject) value;
                for (final Map.Entry<String, JsonValue> entry : jsonObject.entrySet()) {
                    final String property = entry.getKey();
                    final JsonValue subValue = entry.getValue();
                    if (subValue instanceof JsonString) {
                        collection.addEvidence(PODSPEC,
                                String.format("%s.%s", key, property),
                                ((JsonString) subValue).getString(),
                                Confidence.HIGHEST);
                    } else {
                        LOGGER.warn("JSON sub-value not string as expected: {}", subValue);
                    }
                }
            } else {
                LOGGER.warn("JSON value not string or JSON object as expected: {}", value);
            }
        }
    } 
}
