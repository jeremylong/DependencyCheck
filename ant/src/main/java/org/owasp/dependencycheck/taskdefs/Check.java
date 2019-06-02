/*
 * This file is part of dependency-check-ant.
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
package org.owasp.dependencycheck.taskdefs;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.concurrent.NotThreadSafe;

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Project;
import org.apache.tools.ant.types.EnumeratedAttribute;
import org.apache.tools.ant.types.Reference;
import org.apache.tools.ant.types.Resource;
import org.apache.tools.ant.types.ResourceCollection;
import org.apache.tools.ant.types.resources.FileProvider;
import org.apache.tools.ant.types.resources.Resources;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.agent.DependencyCheckScanAgent;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.exception.ExceptionCollection;
import org.owasp.dependencycheck.exception.ReportException;
import org.owasp.dependencycheck.reporting.ReportGenerator.Format;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.impl.StaticLoggerBinder;

/**
 * An Ant task definition to execute dependency-check during an Ant build.
 *
 * @author Jeremy Long
 */
@NotThreadSafe
public class Check extends Update {

    /**
     * Whether the ruby gemspec analyzer should be enabled.
     */
    private Boolean rubygemsAnalyzerEnabled;
    /**
     * Whether or not the Node.js Analyzer is enabled.
     */
    private Boolean nodeAnalyzerEnabled;
    /**
     * Whether or not the Node Audit Analyzer is enabled.
     */
    private Boolean nodeAuditAnalyzerEnabled;
    /**
     * Sets whether or not the Node Audit Analyzer should use a local cache.
     */
    private Boolean nodeAuditAnalyzerUseCache;
    /**
     * Whether or not the RetireJS Analyzer is enabled.
     */
    private Boolean retireJsAnalyzerEnabled;
    /**
     * The URL to the RetireJS JSON data.
     */
    private String retireJsUrl;
    /**
     * The list of filters (regular expressions) used by the RetireJS Analyzer
     * to exclude files that contain matching content..
     */
    @SuppressWarnings("CanBeFinal")
    private List<String> retirejsFilters = new ArrayList<>();
    /**
     * Whether or not the RetireJS Analyzer filters non-vulnerable JS files from
     * the report; default is false.
     */
    private Boolean retirejsFilterNonVulnerable;
    /**
     * Whether or not the Ruby Bundle Audit Analyzer is enabled.
     */
    private Boolean bundleAuditAnalyzerEnabled;
    /**
     * Whether the CMake analyzer should be enabled.
     */
    private Boolean cmakeAnalyzerEnabled;
    /**
     * Whether or not the Open SSL analyzer is enabled.
     */
    private Boolean opensslAnalyzerEnabled;
    /**
     * Whether the python package analyzer should be enabled.
     */
    private Boolean pyPackageAnalyzerEnabled;
    /**
     * Whether the python distribution analyzer should be enabled.
     */
    private Boolean pyDistributionAnalyzerEnabled;
    /**
     * Whether or not the central analyzer is enabled.
     */
    private Boolean centralAnalyzerEnabled;
    /**
     * Whether or not the Central Analyzer should use a local cache.
     */
    private Boolean centralAnalyzerUseCache;
    /**
     * Whether or not the nexus analyzer is enabled.
     */
    private Boolean nexusAnalyzerEnabled;
    /**
     * The URL of a Nexus server's REST API end point
     * (http://domain/nexus/service/local).
     */
    private String nexusUrl;
    /**
     * The username to authenticate to the Nexus Server's REST API Endpoint.
     */
    private String nexusUser;
    /**
     * The password to authenticate to the Nexus Server's REST API Endpoint.
     */
    private String nexusPassword;
    /**
     * Whether or not the defined proxy should be used when connecting to Nexus.
     */
    private Boolean nexusUsesProxy;
    /**
     * Additional ZIP File extensions to add analyze. This should be a
     * comma-separated list of file extensions to treat like ZIP files.
     */
    private String zipExtensions;
    /**
     * The path to dotnet core for .NET assembly analysis.
     */
    private String pathToCore;
    /**
     * The name of the project being analyzed.
     */
    private String projectName = "dependency-check";
    /**
     * Specifies the destination directory for the generated Dependency-Check
     * report.
     */
    private String reportOutputDirectory = ".";
    /**
     * If using the JUNIT report format the junitFailOnCVSS sets the CVSS score
     * threshold that is considered a failure. The default is 0.
     */
    private float junitFailOnCVSS = 0;
    /**
     * Specifies if the build should be failed if a CVSS score above a specified
     * level is identified. The default is 11 which means since the CVSS scores
     * are 0-10, by default the build will never fail and the CVSS score is set
     * to 11. The valid range for the fail build on CVSS is 0 to 11, where
     * anything above 10 will not cause the build to fail.
     */
    private float failBuildOnCVSS = 11;
    /**
     * Sets whether auto-updating of the NVD CVE/CPE data is enabled. It is not
     * recommended that this be turned to false. Default is true.
     */
    private Boolean autoUpdate;
    /**
     * The report format to be generated (HTML, XML, JUNIT, CSV, JSON, ALL).
     * Default is HTML.
     */
    private String reportFormat = "HTML";
    /**
     * The report format to be generated (HTML, XML, JUNIT, CSV, JSON, ALL).
     * Default is HTML.
     */
    private final List<String> reportFormats = new ArrayList<>();
    /**
     * Whether the JSON and XML reports should be pretty printed; the default is
     * false.
     */
    private Boolean prettyPrint = null;

    /**
     * Suppression file path.
     */
    private String suppressionFile = null;
    /**
     * Suppression file paths.
     */
    @SuppressWarnings("CanBeFinal")
    private List<String> suppressionFiles = new ArrayList<>();

    /**
     * The path to the suppression file.
     */
    private String hintsFile;
    /**
     * flag indicating whether or not to show a summary of findings.
     */
    private boolean showSummary = true;
    /**
     * Whether experimental analyzers are enabled.
     */
    private Boolean enableExperimental;
    /**
     * Whether retired analyzers are enabled.
     */
    private Boolean enableRetired;
    /**
     * Whether or not the Jar Analyzer is enabled.
     */
    private Boolean jarAnalyzerEnabled;
    /**
     * Whether or not the Archive Analyzer is enabled.
     */
    private Boolean archiveAnalyzerEnabled;
    /**
     * Whether or not the .NET Nuspec Analyzer is enabled.
     */
    private Boolean nuspecAnalyzerEnabled;
    /**
     * Whether or not the .NET Nuget packages.config file Analyzer is enabled.
     */
    private Boolean nugetconfAnalyzerEnabled;
    /**
     * Whether or not the PHP Composer Analyzer is enabled.
     */
    private Boolean composerAnalyzerEnabled;

    /**
     * Whether or not the .NET Assembly Analyzer is enabled.
     */
    private Boolean assemblyAnalyzerEnabled;
    /**
     * Whether the autoconf analyzer should be enabled.
     */
    private Boolean autoconfAnalyzerEnabled;
    /**
     * Sets the path for the bundle-audit binary.
     */
    private String bundleAuditPath;
    /**
     * Whether or not the CocoaPods Analyzer is enabled.
     */
    private Boolean cocoapodsAnalyzerEnabled;

    /**
     * Whether or not the Swift package Analyzer is enabled.
     */
    private Boolean swiftPackageManagerAnalyzerEnabled;

    /**
     * Whether or not the Sonatype OSS Index analyzer is enabled.
     */
    private Boolean ossindexAnalyzerEnabled;
    /**
     * Whether or not the Sonatype OSS Index analyzer should cache results.
     */
    private Boolean ossindexAnalyzerUseCache;
    /**
     * URL of the Sonatype OSS Index service.
     */
    private String ossindexAnalyzerUrl;

    /**
     * Whether or not the Artifactory Analyzer is enabled.
     */
    private Boolean artifactoryAnalyzerEnabled;
    /**
     * The URL to Artifactory.
     */
    private String artifactoryAnalyzerUrl;
    /**
     * Whether or not Artifactory analysis should use the proxy..
     */
    private Boolean artifactoryAnalyzerUseProxy;
    /**
     * Whether or not Artifactory analysis should be parallelized.
     */
    private Boolean artifactoryAnalyzerParallelAnalysis;
    /**
     * The Artifactory username needed to connect.
     */
    private String artifactoryAnalyzerUsername;
    /**
     * The Artifactory API token needed to connect.
     */
    private String artifactoryAnalyzerApiToken;
    /**
     * The Artifactory bearer token.
     */
    private String artifactoryAnalyzerBearerToken;

    //The following code was copied Apache Ant PathConvert
    //BEGIN COPY from org.apache.tools.ant.taskdefs.PathConvert
    /**
     * Path to be converted
     */
    private Resources path = null;
    /**
     * Reference to path/file set to convert
     */
    private Reference refId = null;

    /**
     * Add an arbitrary ResourceCollection.
     *
     * @param rc the ResourceCollection to add.
     * @since Ant 1.7
     */
    public void add(ResourceCollection rc) {
        if (isReference()) {
            throw new BuildException("Nested elements are not allowed when using the refId attribute.");
        }
        getPath().add(rc);
    }

    /**
     * Add a suppression file.
     * <p>
     * This is called by Ant with the configured {@link SuppressionFile}.
     *
     * @param suppressionFile the suppression file to add.
     */
    public void addConfiguredSuppressionFile(final SuppressionFile suppressionFile) {
        suppressionFiles.add(suppressionFile.getPath());
    }

    /**
     * Returns the path. If the path has not been initialized yet, this class is
     * synchronized, and will instantiate the path object.
     *
     * @return the path
     */
    private synchronized Resources getPath() {
        if (path == null) {
            path = new Resources(getProject());
            path.setCache(true);
        }
        return path;
    }

    /**
     * Learn whether the refId attribute of this element been set.
     *
     * @return true if refId is valid.
     */
    public boolean isReference() {
        return refId != null;
    }

    /**
     * Add a reference to a Path, FileSet, DirSet, or FileList defined
     * elsewhere.
     *
     * @param r the reference to a path, fileset, dirset or filelist.
     */
    public synchronized void setRefId(Reference r) {
        if (path != null) {
            throw new BuildException("Nested elements are not allowed when using the refId attribute.");
        }
        refId = r;
    }

    /**
     * If this is a reference, this method will add the referenced resource
     * collection to the collection of paths.
     *
     * @throws BuildException if the reference is not to a resource collection
     */
    private void dealWithReferences() throws BuildException {
        if (isReference()) {
            final Object o = refId.getReferencedObject(getProject());
            if (!(o instanceof ResourceCollection)) {
                throw new BuildException("refId '" + refId.getRefId()
                        + "' does not refer to a resource collection.");
            }
            getPath().add((ResourceCollection) o);
        }
    }
    // END COPY from org.apache.tools.ant.taskdefs

    /**
     * Construct a new DependencyCheckTask.
     */
    public Check() {
        super();
        // Call this before Dependency Check Core starts logging anything - this way, all SLF4J messages from
        // core end up coming through this tasks logger
        StaticLoggerBinder.getSingleton().setTask(this);
    }

    /**
     * Get the value of projectName.
     *
     * @return the value of projectName
     */
    public String getProjectName() {
        if (projectName == null) {
            projectName = "";
        }
        return projectName;
    }

    /**
     * Set the value of projectName.
     *
     * @param projectName new value of projectName
     */
    public void setProjectName(String projectName) {
        this.projectName = projectName;
    }

    /**
     * Get the value of reportOutputDirectory.
     *
     * @return the value of reportOutputDirectory
     */
    public String getReportOutputDirectory() {
        return reportOutputDirectory;
    }

    /**
     * Set the value of reportOutputDirectory.
     *
     * @param reportOutputDirectory new value of reportOutputDirectory
     */
    public void setReportOutputDirectory(String reportOutputDirectory) {
        this.reportOutputDirectory = reportOutputDirectory;
    }

    /**
     * Get the value of failBuildOnCVSS.
     *
     * @return the value of failBuildOnCVSS
     */
    public float getFailBuildOnCVSS() {
        return failBuildOnCVSS;
    }

    /**
     * Set the value of failBuildOnCVSS.
     *
     * @param failBuildOnCVSS new value of failBuildOnCVSS
     */
    public void setFailBuildOnCVSS(float failBuildOnCVSS) {
        this.failBuildOnCVSS = failBuildOnCVSS;
    }

    /**
     * Get the value of junitFailOnCVSS.
     *
     * @return the value of junitFailOnCVSS
     */
    public float getJunitFailOnCVSS() {
        return junitFailOnCVSS;
    }

    /**
     * Set the value of junitFailOnCVSS.
     *
     * @param junitFailOnCVSS new value of junitFailOnCVSS
     */
    public void setJunitFailOnCVSS(float junitFailOnCVSS) {
        this.junitFailOnCVSS = junitFailOnCVSS;
    }

    /**
     * Get the value of autoUpdate.
     *
     * @return the value of autoUpdate
     */
    public Boolean isAutoUpdate() {
        return autoUpdate;
    }

    /**
     * Set the value of autoUpdate.
     *
     * @param autoUpdate new value of autoUpdate
     */
    public void setAutoUpdate(Boolean autoUpdate) {
        this.autoUpdate = autoUpdate;
    }

    /**
     * Get the value of prettyPrint.
     *
     * @return the value of prettyPrint
     */
    public Boolean isPrettyPrint() {
        return prettyPrint;
    }

    /**
     * Set the value of prettyPrint.
     *
     * @param prettyPrint new value of prettyPrint
     */
    public void setPrettyPrint(boolean prettyPrint) {
        this.prettyPrint = prettyPrint;
    }

    /**
     * Set the value of reportFormat.
     *
     * @param reportFormat new value of reportFormat
     */
    public void setReportFormat(ReportFormats reportFormat) {
        this.reportFormat = reportFormat.getValue();
        this.reportFormats.add(this.reportFormat);
    }

    /**
     * Get the value of reportFormats.
     *
     * @return the value of reportFormats
     */
    public List<String> getReportFormats() {
        if (reportFormats.isEmpty()) {
            this.reportFormats.add(this.reportFormat);
        }
        return this.reportFormats;
    }

    /**
     * Gets suppression file paths.
     *
     * @return the suppression files.
     */
    public List<String> getSuppressionFiles() {
        return suppressionFiles;
    }

    /**
     * Set the value of suppressionFile.
     *
     * @param suppressionFile new value of suppressionFile
     */
    public void setSuppressionFile(String suppressionFile) {
        this.suppressionFile = suppressionFile;
        suppressionFiles.add(suppressionFile);
    }

    /**
     * Get the value of hintsFile.
     *
     * @return the value of hintsFile
     */
    public String getHintsFile() {
        return hintsFile;
    }

    /**
     * Set the value of hintsFile.
     *
     * @param hintsFile new value of hintsFile
     */
    public void setHintsFile(String hintsFile) {
        this.hintsFile = hintsFile;
    }

    /**
     * Get the value of showSummary.
     *
     * @return the value of showSummary
     */
    public boolean isShowSummary() {
        return showSummary;
    }

    /**
     * Set the value of showSummary.
     *
     * @param showSummary new value of showSummary
     */
    public void setShowSummary(boolean showSummary) {
        this.showSummary = showSummary;
    }

    /**
     * Get the value of enableExperimental.
     *
     * @return the value of enableExperimental
     */
    public Boolean isEnableExperimental() {
        return enableExperimental;
    }

    /**
     * Set the value of enableExperimental.
     *
     * @param enableExperimental new value of enableExperimental
     */
    public void setEnableExperimental(Boolean enableExperimental) {
        this.enableExperimental = enableExperimental;
    }

    /**
     * Get the value of enableRetired.
     *
     * @return the value of enableRetired
     */
    public Boolean isEnableRetired() {
        return enableRetired;
    }

    /**
     * Set the value of enableRetired.
     *
     * @param enableRetired new value of enableRetired
     */
    public void setEnableRetired(Boolean enableRetired) {
        this.enableRetired = enableRetired;
    }

    /**
     * Returns whether or not the analyzer is enabled.
     *
     * @return true if the analyzer is enabled
     */
    public Boolean isJarAnalyzerEnabled() {
        return jarAnalyzerEnabled;
    }

    /**
     * Sets whether or not the analyzer is enabled.
     *
     * @param jarAnalyzerEnabled the value of the new setting
     */
    public void setJarAnalyzerEnabled(Boolean jarAnalyzerEnabled) {
        this.jarAnalyzerEnabled = jarAnalyzerEnabled;
    }

    /**
     * Returns whether or not the analyzer is enabled.
     *
     * @return true if the analyzer is enabled
     */
    public Boolean isArchiveAnalyzerEnabled() {
        return archiveAnalyzerEnabled;
    }

    /**
     * Sets whether or not the analyzer is enabled.
     *
     * @param archiveAnalyzerEnabled the value of the new setting
     */
    public void setArchiveAnalyzerEnabled(Boolean archiveAnalyzerEnabled) {
        this.archiveAnalyzerEnabled = archiveAnalyzerEnabled;
    }

    /**
     * Returns whether or not the analyzer is enabled.
     *
     * @return true if the analyzer is enabled
     */
    public Boolean isAssemblyAnalyzerEnabled() {
        return assemblyAnalyzerEnabled;
    }

    /**
     * Sets whether or not the analyzer is enabled.
     *
     * @param assemblyAnalyzerEnabled the value of the new setting
     */
    public void setAssemblyAnalyzerEnabled(Boolean assemblyAnalyzerEnabled) {
        this.assemblyAnalyzerEnabled = assemblyAnalyzerEnabled;
    }

    /**
     * Returns whether or not the analyzer is enabled.
     *
     * @return true if the analyzer is enabled
     */
    public Boolean isNuspecAnalyzerEnabled() {
        return nuspecAnalyzerEnabled;
    }

    /**
     * Returns whether or not the analyzer is enabled.
     *
     * @return true if the analyzer is enabled
     */
    public Boolean isNugetconfAnalyzerEnabled() {
        return nugetconfAnalyzerEnabled;
    }

    /**
     * Sets whether or not the analyzer is enabled.
     *
     * @param nuspecAnalyzerEnabled the value of the new setting
     */
    public void setNuspecAnalyzerEnabled(Boolean nuspecAnalyzerEnabled) {
        this.nuspecAnalyzerEnabled = nuspecAnalyzerEnabled;
    }

    /**
     * Sets whether or not the analyzer is enabled.
     *
     * @param nugetconfAnalyzerEnabled the value of the new setting
     */
    public void setNugetconfAnalyzerEnabled(Boolean nugetconfAnalyzerEnabled) {
        this.nugetconfAnalyzerEnabled = nugetconfAnalyzerEnabled;
    }

    /**
     * Get the value of composerAnalyzerEnabled.
     *
     * @return the value of composerAnalyzerEnabled
     */
    public Boolean isComposerAnalyzerEnabled() {
        return composerAnalyzerEnabled;
    }

    /**
     * Set the value of composerAnalyzerEnabled.
     *
     * @param composerAnalyzerEnabled new value of composerAnalyzerEnabled
     */
    public void setComposerAnalyzerEnabled(Boolean composerAnalyzerEnabled) {
        this.composerAnalyzerEnabled = composerAnalyzerEnabled;
    }

    /**
     * Get the value of autoconfAnalyzerEnabled.
     *
     * @return the value of autoconfAnalyzerEnabled
     */
    public Boolean isAutoconfAnalyzerEnabled() {
        return autoconfAnalyzerEnabled;
    }

    /**
     * Set the value of autoconfAnalyzerEnabled.
     *
     * @param autoconfAnalyzerEnabled new value of autoconfAnalyzerEnabled
     */
    public void setAutoconfAnalyzerEnabled(Boolean autoconfAnalyzerEnabled) {
        this.autoconfAnalyzerEnabled = autoconfAnalyzerEnabled;
    }

    /**
     * Get the value of cmakeAnalyzerEnabled.
     *
     * @return the value of cmakeAnalyzerEnabled
     */
    public Boolean isCMakeAnalyzerEnabled() {
        return cmakeAnalyzerEnabled;
    }

    /**
     * Set the value of cmakeAnalyzerEnabled.
     *
     * @param cmakeAnalyzerEnabled new value of cmakeAnalyzerEnabled
     */
    public void setCMakeAnalyzerEnabled(Boolean cmakeAnalyzerEnabled) {
        this.cmakeAnalyzerEnabled = cmakeAnalyzerEnabled;
    }

    /**
     * Returns if the Bundle Audit Analyzer is enabled.
     *
     * @return if the Bundle Audit Analyzer is enabled.
     */
    public Boolean isBundleAuditAnalyzerEnabled() {
        return bundleAuditAnalyzerEnabled;
    }

    /**
     * Sets if the Bundle Audit Analyzer is enabled.
     *
     * @param bundleAuditAnalyzerEnabled whether or not the analyzer should be
     * enabled
     */
    public void setBundleAuditAnalyzerEnabled(Boolean bundleAuditAnalyzerEnabled) {
        this.bundleAuditAnalyzerEnabled = bundleAuditAnalyzerEnabled;
    }

    /**
     * Returns the path to the bundle audit executable.
     *
     * @return the path to the bundle audit executable
     */
    public String getBundleAuditPath() {
        return bundleAuditPath;
    }

    /**
     * Sets the path to the bundle audit executable.
     *
     * @param bundleAuditPath the path to the bundle audit executable
     */
    public void setBundleAuditPath(String bundleAuditPath) {
        this.bundleAuditPath = bundleAuditPath;
    }

    /**
     * Returns if the cocoapods analyzer is enabled.
     *
     * @return if the cocoapods analyzer is enabled
     */
    public boolean isCocoapodsAnalyzerEnabled() {
        return cocoapodsAnalyzerEnabled;
    }

    /**
     * Sets whether or not the cocoapods analyzer is enabled.
     *
     * @param cocoapodsAnalyzerEnabled the state of the cocoapods analyzer
     */
    public void setCocoapodsAnalyzerEnabled(Boolean cocoapodsAnalyzerEnabled) {
        this.cocoapodsAnalyzerEnabled = cocoapodsAnalyzerEnabled;
    }

    /**
     * Returns whether or not the Swift package Analyzer is enabled.
     *
     * @return whether or not the Swift package Analyzer is enabled
     */
    public Boolean isSwiftPackageManagerAnalyzerEnabled() {
        return swiftPackageManagerAnalyzerEnabled;
    }

    /**
     * Sets the enabled state of the swift package manager analyzer.
     *
     * @param swiftPackageManagerAnalyzerEnabled the enabled state of the swift
     * package manager
     */
    public void setSwiftPackageManagerAnalyzerEnabled(Boolean swiftPackageManagerAnalyzerEnabled) {
        this.swiftPackageManagerAnalyzerEnabled = swiftPackageManagerAnalyzerEnabled;
    }

    /**
     * Get the value of opensslAnalyzerEnabled.
     *
     * @return the value of opensslAnalyzerEnabled
     */
    public Boolean isOpensslAnalyzerEnabled() {
        return opensslAnalyzerEnabled;
    }

    /**
     * Set the value of opensslAnalyzerEnabled.
     *
     * @param opensslAnalyzerEnabled new value of opensslAnalyzerEnabled
     */
    public void setOpensslAnalyzerEnabled(Boolean opensslAnalyzerEnabled) {
        this.opensslAnalyzerEnabled = opensslAnalyzerEnabled;
    }

    /**
     * Get the value of nodeAnalyzerEnabled.
     *
     * @return the value of nodeAnalyzerEnabled
     */
    public Boolean isNodeAnalyzerEnabled() {
        return nodeAnalyzerEnabled;
    }

    /**
     * Set the value of nodeAnalyzerEnabled.
     *
     * @param nodeAnalyzerEnabled new value of nodeAnalyzerEnabled
     */
    public void setNodeAnalyzerEnabled(Boolean nodeAnalyzerEnabled) {
        this.nodeAnalyzerEnabled = nodeAnalyzerEnabled;
    }

    /**
     * Get the value of nodeAnalyzerEnabled.
     *
     * @return the value of nodeAnalyzerEnabled
     * @deprecated As of release 3.3.3, replaced by
     * {@link #isNodeAuditAnalyzerEnabled()}
     */
    @Deprecated
    public Boolean isNspAnalyzerEnabled() {
        log("The NspAnalyzerEnabled configuration has been deprecated and replaced by NodeAuditAnalyzerEnabled", Project.MSG_ERR);
        log("The NspAnalyzerEnabled configuration will be removed in the next major release");
        return nodeAnalyzerEnabled;
    }

    /**
     * Set the value of nodeAnalyzerEnabled.
     *
     * @param nodeAnalyzerEnabled new value of nodeAnalyzerEnabled
     * @deprecated As of release 3.3.3, replaced by
     * {@link #setNodeAuditAnalyzerEnabled(java.lang.Boolean)}
     */
    @Deprecated
    public void setNspAnalyzerEnabled(Boolean nodeAnalyzerEnabled) {
        log("The NspAnalyzerEnabled configuration has been deprecated and replaced by NodeAuditAnalyzerEnabled", Project.MSG_ERR);
        log("The NspAnalyzerEnabled configuration will be removed in the next major release");
        this.nodeAnalyzerEnabled = nodeAnalyzerEnabled;
    }

    /**
     * Get the value of nodeAuditAnalyzerEnabled.
     *
     * @return the value of nodeAuditAnalyzerEnabled
     */
    public Boolean isNodeAuditAnalyzerEnabled() {
        return nodeAuditAnalyzerEnabled;
    }

    /**
     * Set the value of nodeAuditAnalyzerEnabled.
     *
     * @param nodeAuditAnalyzerEnabled new value of nodeAuditAnalyzerEnabled
     */
    public void setNodeAuditAnalyzerEnabled(Boolean nodeAuditAnalyzerEnabled) {
        this.nodeAuditAnalyzerEnabled = nodeAuditAnalyzerEnabled;
    }

    /**
     * Get the value of nodeAuditAnalyzerUseCache.
     *
     * @return the value of nodeAuditAnalyzerUseCache
     */
    public Boolean isNodeAuditAnalyzerUseCache() {
        return nodeAuditAnalyzerUseCache;
    }

    /**
     * Set the value of nodeAuditAnalyzerUseCache.
     *
     * @param nodeAuditAnalyzerUseCache new value of nodeAuditAnalyzerUseCache
     */
    public void setNodeAuditAnalyzerUseCache(Boolean nodeAuditAnalyzerUseCache) {
        this.nodeAuditAnalyzerUseCache = nodeAuditAnalyzerUseCache;
    }

    /**
     * Get the value of retireJsAnalyzerEnabled.
     *
     * @return the value of retireJsAnalyzerEnabled
     */
    public Boolean isRetireJsAnalyzerEnabled() {
        return retireJsAnalyzerEnabled;
    }

    /**
     * Set the value of retireJsAnalyzerEnabled.
     *
     * @param retireJsAnalyzerEnabled new value of retireJsAnalyzerEnabled
     */
    public void setRetireJsAnalyzerEnabled(Boolean retireJsAnalyzerEnabled) {
        this.retireJsAnalyzerEnabled = retireJsAnalyzerEnabled;
    }

    /**
     * Get the value of Retire JS repository URL.
     *
     * @return the value of retireJsUrl
     */
    public String getRetireJsUrl() {
        return retireJsUrl;
    }

    /**
     * Set the value of the Retire JS repository URL.
     *
     * @param retireJsUrl new value of retireJsUrl
     */
    public void setRetireJsUrl(String retireJsUrl) {
        this.retireJsUrl = retireJsUrl;
    }

    /**
     * Get the value of retirejsFilterNonVulnerable.
     *
     * @return the value of retirejsFilterNonVulnerable
     */
    public Boolean isRetirejsFilterNonVulnerable() {
        return retirejsFilterNonVulnerable;
    }

    /**
     * Set the value of retirejsFilterNonVulnerable.
     *
     * @param retirejsFilterNonVulnerable new value of
     * retirejsFilterNonVulnerable
     */
    public void setRetirejsFilterNonVulnerable(Boolean retirejsFilterNonVulnerable) {
        this.retirejsFilterNonVulnerable = retirejsFilterNonVulnerable;
    }

    /**
     * Gets retire JS Analyzers file content filters.
     *
     * @return retire JS Analyzers file content filters
     */
    public List<String> getRetirejsFilters() {
        return retirejsFilters;
    }

    /**
     * Add a regular expression to the set of retire JS content filters.
     * <p>
     * This is called by Ant.
     *
     * @param retirejsFilter the regular expression used to filter based on file
     * content
     */
    public void addConfiguredRetirejsFilter(final RetirejsFilter retirejsFilter) {
        retirejsFilters.add(retirejsFilter.getRegex());
    }

    /**
     * Get the value of rubygemsAnalyzerEnabled.
     *
     * @return the value of rubygemsAnalyzerEnabled
     */
    public Boolean isRubygemsAnalyzerEnabled() {
        return rubygemsAnalyzerEnabled;
    }

    /**
     * Set the value of rubygemsAnalyzerEnabled.
     *
     * @param rubygemsAnalyzerEnabled new value of rubygemsAnalyzerEnabled
     */
    public void setRubygemsAnalyzerEnabled(Boolean rubygemsAnalyzerEnabled) {
        this.rubygemsAnalyzerEnabled = rubygemsAnalyzerEnabled;
    }

    /**
     * Get the value of pyPackageAnalyzerEnabled.
     *
     * @return the value of pyPackageAnalyzerEnabled
     */
    public Boolean isPyPackageAnalyzerEnabled() {
        return pyPackageAnalyzerEnabled;
    }

    /**
     * Set the value of pyPackageAnalyzerEnabled.
     *
     * @param pyPackageAnalyzerEnabled new value of pyPackageAnalyzerEnabled
     */
    public void setPyPackageAnalyzerEnabled(Boolean pyPackageAnalyzerEnabled) {
        this.pyPackageAnalyzerEnabled = pyPackageAnalyzerEnabled;
    }

    /**
     * Get the value of pyDistributionAnalyzerEnabled.
     *
     * @return the value of pyDistributionAnalyzerEnabled
     */
    public Boolean isPyDistributionAnalyzerEnabled() {
        return pyDistributionAnalyzerEnabled;
    }

    /**
     * Set the value of pyDistributionAnalyzerEnabled.
     *
     * @param pyDistributionAnalyzerEnabled new value of
     * pyDistributionAnalyzerEnabled
     */
    public void setPyDistributionAnalyzerEnabled(Boolean pyDistributionAnalyzerEnabled) {
        this.pyDistributionAnalyzerEnabled = pyDistributionAnalyzerEnabled;
    }

    /**
     * Get the value of centralAnalyzerEnabled.
     *
     * @return the value of centralAnalyzerEnabled
     */
    public Boolean isCentralAnalyzerEnabled() {
        return centralAnalyzerEnabled;
    }

    /**
     * Set the value of centralAnalyzerEnabled.
     *
     * @param centralAnalyzerEnabled new value of centralAnalyzerEnabled
     */
    public void setCentralAnalyzerEnabled(Boolean centralAnalyzerEnabled) {
        this.centralAnalyzerEnabled = centralAnalyzerEnabled;
    }

    /**
     * Get the value of centralAnalyzerUseCache.
     *
     * @return the value of centralAnalyzerUseCache
     */
    public Boolean isCentralAnalyzerUseCache() {
        return centralAnalyzerUseCache;
    }

    /**
     * Set the value of centralAnalyzerUseCache.
     *
     * @param centralAnalyzerUseCache new value of centralAnalyzerUseCache
     */
    public void setCentralAnalyzerUseCache(Boolean centralAnalyzerUseCache) {
        this.centralAnalyzerUseCache = centralAnalyzerUseCache;
    }

    /**
     * Get the value of nexusAnalyzerEnabled.
     *
     * @return the value of nexusAnalyzerEnabled
     */
    public Boolean isNexusAnalyzerEnabled() {
        return nexusAnalyzerEnabled;
    }

    /**
     * Set the value of nexusAnalyzerEnabled.
     *
     * @param nexusAnalyzerEnabled new value of nexusAnalyzerEnabled
     */
    public void setNexusAnalyzerEnabled(Boolean nexusAnalyzerEnabled) {
        this.nexusAnalyzerEnabled = nexusAnalyzerEnabled;
    }

    /**
     * Get the value of nexusUrl.
     *
     * @return the value of nexusUrl
     */
    public String getNexusUrl() {
        return nexusUrl;
    }

    /**
     * Set the value of nexusUrl.
     *
     * @param nexusUrl new value of nexusUrl
     */
    public void setNexusUrl(String nexusUrl) {
        this.nexusUrl = nexusUrl;
    }

    /**
     * Get the value of nexusUser.
     *
     * @return the value of nexusUser
     */
    public String getNexusUser() {
        return nexusUser;
    }

    /**
     * Set the value of nexusUser.
     *
     * @param nexusUser new value of nexusUser
     */
    public void setNexusUser(String nexusUser) {
        this.nexusUser = nexusUser;
    }

    /**
     * Get the value of nexusPassword.
     *
     * @return the value of nexusPassword
     */
    public String getNexusPassword() {
        return nexusPassword;
    }

    /**
     * Set the value of nexusPassword.
     *
     * @param nexusPassword new value of nexusPassword
     */
    public void setNexusPassword(String nexusPassword) {
        this.nexusPassword = nexusPassword;
    }

    /**
     * Get the value of nexusUsesProxy.
     *
     * @return the value of nexusUsesProxy
     */
    public Boolean isNexusUsesProxy() {
        return nexusUsesProxy;
    }

    /**
     * Set the value of nexusUsesProxy.
     *
     * @param nexusUsesProxy new value of nexusUsesProxy
     */
    public void setNexusUsesProxy(Boolean nexusUsesProxy) {
        this.nexusUsesProxy = nexusUsesProxy;
    }

    /**
     * Get the value of zipExtensions.
     *
     * @return the value of zipExtensions
     */
    public String getZipExtensions() {
        return zipExtensions;
    }

    /**
     * Set the value of zipExtensions.
     *
     * @param zipExtensions new value of zipExtensions
     */
    public void setZipExtensions(String zipExtensions) {
        this.zipExtensions = zipExtensions;
    }

    /**
     * Get the value of pathToCore.
     *
     * @return the value of pathToCore
     */
    public String getPathToDotnetCore() {
        return pathToCore;
    }

    /**
     * Set the value of pathToCore.
     *
     * @param pathToCore new value of pathToCore
     */
    public void setPathToDotnetCore(String pathToCore) {
        this.pathToCore = pathToCore;
    }

    /**
     * Get value of {@link #ossindexAnalyzerEnabled}.
     *
     * @return the value of ossindexAnalyzerEnabled
     */
    public Boolean isOssindexAnalyzerEnabled() {
        return ossindexAnalyzerEnabled;
    }

    /**
     * Set value of {@link #ossindexAnalyzerEnabled}.
     *
     * @param ossindexAnalyzerEnabled new value of ossindexAnalyzerEnabled
     */
    public void setOssindexAnalyzerEnabled(Boolean ossindexAnalyzerEnabled) {
        this.ossindexAnalyzerEnabled = ossindexAnalyzerEnabled;
    }

    /**
     * Get value of {@link #ossindexAnalyzerUseCache}.
     *
     * @return the value of ossindexAnalyzerUseCache
     */
    public Boolean isOssindexAnalyzerUseCache() {
        return ossindexAnalyzerUseCache;
    }

    /**
     * Set value of {@link #ossindexAnalyzerUseCache}.
     *
     * @param ossindexAnalyzerUseCache new value of ossindexAnalyzerUseCache
     */
    public void setOssindexAnalyzerUseCache(Boolean ossindexAnalyzerUseCache) {
        this.ossindexAnalyzerUseCache = ossindexAnalyzerUseCache;
    }

    /**
     * Get value of {@link #ossindexAnalyzerUrl}.
     *
     * @return the value of ossindexAnalyzerUrl
     */
    public String getOssindexAnalyzerUrl() {
        return ossindexAnalyzerUrl;
    }

    /**
     * Set value of {@link #ossindexAnalyzerUrl}.
     *
     * @param ossindexAnalyzerUrl new value of ossindexAnalyzerUrl
     */
    public void setOssindexAnalyzerUrl(String ossindexAnalyzerUrl) {
        this.ossindexAnalyzerUrl = ossindexAnalyzerUrl;
    }

    /**
     * Returns the value of cmakeAnalyzerEnabled.
     *
     * @return the value of cmakeAnalyzerEnabled
     */
    public Boolean getCmakeAnalyzerEnabled() {
        return cmakeAnalyzerEnabled;
    }

    /**
     * Set the value of cmakeAnalyzerEnabled.
     *
     * @param cmakeAnalyzerEnabled new value of cmakeAnalyzerEnabled
     */
    public void setCmakeAnalyzerEnabled(Boolean cmakeAnalyzerEnabled) {
        this.cmakeAnalyzerEnabled = cmakeAnalyzerEnabled;
    }

    /**
     * Returns the value of artifactoryAnalyzerEnabled.
     *
     * @return the value of artifactoryAnalyzerEnabled
     */
    public Boolean getArtifactoryAnalyzerEnabled() {
        return artifactoryAnalyzerEnabled;
    }

    /**
     * Set the value of artifactoryAnalyzerEnabled.
     *
     * @param artifactoryAnalyzerEnabled new value of artifactoryAnalyzerEnabled
     */
    public void setArtifactoryAnalyzerEnabled(Boolean artifactoryAnalyzerEnabled) {
        this.artifactoryAnalyzerEnabled = artifactoryAnalyzerEnabled;
    }

    /**
     * Returns the value of artifactoryAnalyzerUrl.
     *
     * @return the value of artifactoryAnalyzerUrl
     */
    public String getArtifactoryAnalyzerUrl() {
        return artifactoryAnalyzerUrl;
    }

    /**
     * Set the value of artifactoryAnalyzerUrl.
     *
     * @param artifactoryAnalyzerUrl new value of artifactoryAnalyzerUrl
     */
    public void setArtifactoryAnalyzerUrl(String artifactoryAnalyzerUrl) {
        this.artifactoryAnalyzerUrl = artifactoryAnalyzerUrl;
    }

    /**
     * Returns the value of artifactoryAnalyzerUseProxy.
     *
     * @return the value of artifactoryAnalyzerUseProxy
     */
    public Boolean getArtifactoryAnalyzerUseProxy() {
        return artifactoryAnalyzerUseProxy;
    }

    /**
     * Set the value of artifactoryAnalyzerUseProxy.
     *
     * @param artifactoryAnalyzerUseProxy new value of
     * artifactoryAnalyzerUseProxy
     */
    public void setArtifactoryAnalyzerUseProxy(Boolean artifactoryAnalyzerUseProxy) {
        this.artifactoryAnalyzerUseProxy = artifactoryAnalyzerUseProxy;
    }

    /**
     * Returns the value of artifactoryAnalyzerParallelAnalysis.
     *
     * @return the value of artifactoryAnalyzerParallelAnalysis
     */
    public Boolean getArtifactoryAnalyzerParallelAnalysis() {
        return artifactoryAnalyzerParallelAnalysis;
    }

    /**
     * Set the value of artifactoryAnalyzerParallelAnalysis.
     *
     * @param artifactoryAnalyzerParallelAnalysis new value of
     * artifactoryAnalyzerParallelAnalysis
     */
    public void setArtifactoryAnalyzerParallelAnalysis(Boolean artifactoryAnalyzerParallelAnalysis) {
        this.artifactoryAnalyzerParallelAnalysis = artifactoryAnalyzerParallelAnalysis;
    }

    /**
     * Returns the value of artifactoryAnalyzerUsername.
     *
     * @return the value of artifactoryAnalyzerUsername
     */
    public String getArtifactoryAnalyzerUsername() {
        return artifactoryAnalyzerUsername;
    }

    /**
     * Set the value of artifactoryAnalyzerUsername.
     *
     * @param artifactoryAnalyzerUsername new value of
     * artifactoryAnalyzerUsername
     */
    public void setArtifactoryAnalyzerUsername(String artifactoryAnalyzerUsername) {
        this.artifactoryAnalyzerUsername = artifactoryAnalyzerUsername;
    }

    /**
     * Returns the value of artifactoryAnalyzerApiToken.
     *
     * @return the value of artifactoryAnalyzerApiToken
     */
    public String getArtifactoryAnalyzerApiToken() {
        return artifactoryAnalyzerApiToken;
    }

    /**
     * Set the value of artifactoryAnalyzerApiToken.
     *
     * @param artifactoryAnalyzerApiToken new value of
     * artifactoryAnalyzerApiToken
     */
    public void setArtifactoryAnalyzerApiToken(String artifactoryAnalyzerApiToken) {
        this.artifactoryAnalyzerApiToken = artifactoryAnalyzerApiToken;
    }

    /**
     * Returns the value of artifactoryAnalyzerBearerToken.
     *
     * @return the value of artifactoryAnalyzerBearerToken
     */
    public String getArtifactoryAnalyzerBearerToken() {
        return artifactoryAnalyzerBearerToken;
    }

    /**
     * Set the value of artifactoryAnalyzerBearerToken.
     *
     * @param artifactoryAnalyzerBearerToken new value of
     * artifactoryAnalyzerBearerToken
     */
    public void setArtifactoryAnalyzerBearerToken(String artifactoryAnalyzerBearerToken) {
        this.artifactoryAnalyzerBearerToken = artifactoryAnalyzerBearerToken;
    }

    @Override
    public void execute() throws BuildException {
        dealWithReferences();
        validateConfiguration();
        populateSettings();
        try (Engine engine = new Engine(Check.class.getClassLoader(), getSettings())) {
            for (Resource resource : getPath()) {
                final FileProvider provider = resource.as(FileProvider.class);
                if (provider != null) {
                    final File file = provider.getFile();
                    if (file != null && file.exists()) {
                        engine.scan(file);
                    }
                }
            }

            try {
                engine.analyzeDependencies();
            } catch (ExceptionCollection ex) {
                if (this.isFailOnError()) {
                    throw new BuildException(ex);
                }
            }
            for (String format : getReportFormats()) {
                engine.writeReports(getProjectName(), new File(reportOutputDirectory), format);
            }

            if (this.failBuildOnCVSS <= 10) {
                checkForFailure(engine.getDependencies());
            }
            if (this.showSummary) {
                DependencyCheckScanAgent.showSummary(engine.getDependencies());
            }
        } catch (DatabaseException ex) {
            final String msg = "Unable to connect to the dependency-check database; analysis has stopped";
            if (this.isFailOnError()) {
                throw new BuildException(msg, ex);
            }
            log(msg, ex, Project.MSG_ERR);
        } catch (ReportException ex) {
            final String msg = "Unable to generate the dependency-check report";
            if (this.isFailOnError()) {
                throw new BuildException(msg, ex);
            }
            log(msg, ex, Project.MSG_ERR);
        } finally {
            getSettings().cleanup();
        }
    }

    /**
     * Validate the configuration to ensure the parameters have been properly
     * configured/initialized.
     *
     * @throws BuildException if the task was not configured correctly.
     */
    private synchronized void validateConfiguration() throws BuildException {
        if (path == null) {
            throw new BuildException("No project dependencies have been defined to analyze.");
        }
        if (failBuildOnCVSS < 0 || failBuildOnCVSS > 11) {
            throw new BuildException("Invalid configuration, failBuildOnCVSS must be between 0 and 11.");
        }
    }

    /**
     * Takes the properties supplied and updates the dependency-check settings.
     * Additionally, this sets the system properties required to change the
     * proxy server, port, and connection timeout.
     *
     * @throws BuildException thrown when an invalid setting is configured.
     */
    @Override
    protected void populateSettings() throws BuildException {
        super.populateSettings();
        getSettings().setBooleanIfNotNull(Settings.KEYS.AUTO_UPDATE, autoUpdate);
        getSettings().setArrayIfNotEmpty(Settings.KEYS.SUPPRESSION_FILE, suppressionFiles);
        getSettings().setStringIfNotEmpty(Settings.KEYS.HINTS_FILE, hintsFile);
        getSettings().setBooleanIfNotNull(Settings.KEYS.ANALYZER_EXPERIMENTAL_ENABLED, enableExperimental);
        getSettings().setBooleanIfNotNull(Settings.KEYS.PRETTY_PRINT, prettyPrint);
        getSettings().setBooleanIfNotNull(Settings.KEYS.ANALYZER_RETIRED_ENABLED, enableRetired);
        getSettings().setBooleanIfNotNull(Settings.KEYS.ANALYZER_JAR_ENABLED, jarAnalyzerEnabled);
        getSettings().setBooleanIfNotNull(Settings.KEYS.ANALYZER_PYTHON_DISTRIBUTION_ENABLED, pyDistributionAnalyzerEnabled);
        getSettings().setBooleanIfNotNull(Settings.KEYS.ANALYZER_PYTHON_PACKAGE_ENABLED, pyPackageAnalyzerEnabled);
        getSettings().setBooleanIfNotNull(Settings.KEYS.ANALYZER_RUBY_GEMSPEC_ENABLED, rubygemsAnalyzerEnabled);
        getSettings().setBooleanIfNotNull(Settings.KEYS.ANALYZER_OPENSSL_ENABLED, opensslAnalyzerEnabled);
        getSettings().setBooleanIfNotNull(Settings.KEYS.ANALYZER_CMAKE_ENABLED, cmakeAnalyzerEnabled);

        getSettings().setBooleanIfNotNull(Settings.KEYS.ANALYZER_ARTIFACTORY_ENABLED, artifactoryAnalyzerEnabled);
        getSettings().setStringIfNotEmpty(Settings.KEYS.ANALYZER_ARTIFACTORY_URL, artifactoryAnalyzerUrl);
        getSettings().setBooleanIfNotNull(Settings.KEYS.ANALYZER_ARTIFACTORY_USES_PROXY, artifactoryAnalyzerUseProxy);
        getSettings().setBooleanIfNotNull(Settings.KEYS.ANALYZER_ARTIFACTORY_PARALLEL_ANALYSIS, artifactoryAnalyzerParallelAnalysis);
        getSettings().setStringIfNotEmpty(Settings.KEYS.ANALYZER_ARTIFACTORY_API_USERNAME, artifactoryAnalyzerUsername);
        getSettings().setStringIfNotEmpty(Settings.KEYS.ANALYZER_ARTIFACTORY_API_TOKEN, artifactoryAnalyzerApiToken);
        getSettings().setStringIfNotEmpty(Settings.KEYS.ANALYZER_ARTIFACTORY_BEARER_TOKEN, artifactoryAnalyzerBearerToken);

        getSettings().setBooleanIfNotNull(Settings.KEYS.ANALYZER_SWIFT_PACKAGE_MANAGER_ENABLED, swiftPackageManagerAnalyzerEnabled);
        getSettings().setBooleanIfNotNull(Settings.KEYS.ANALYZER_COCOAPODS_ENABLED, cocoapodsAnalyzerEnabled);
        getSettings().setBooleanIfNotNull(Settings.KEYS.ANALYZER_BUNDLE_AUDIT_ENABLED, bundleAuditAnalyzerEnabled);
        getSettings().setStringIfNotNull(Settings.KEYS.ANALYZER_BUNDLE_AUDIT_PATH, bundleAuditPath);
        getSettings().setBooleanIfNotNull(Settings.KEYS.ANALYZER_AUTOCONF_ENABLED, autoconfAnalyzerEnabled);
        getSettings().setBooleanIfNotNull(Settings.KEYS.ANALYZER_COMPOSER_LOCK_ENABLED, composerAnalyzerEnabled);
        getSettings().setBooleanIfNotNull(Settings.KEYS.ANALYZER_NODE_PACKAGE_ENABLED, nodeAnalyzerEnabled);
        getSettings().setBooleanIfNotNull(Settings.KEYS.ANALYZER_NODE_AUDIT_ENABLED, nodeAuditAnalyzerEnabled);
        getSettings().setBooleanIfNotNull(Settings.KEYS.ANALYZER_NODE_AUDIT_USE_CACHE, nodeAuditAnalyzerUseCache);
        getSettings().setBooleanIfNotNull(Settings.KEYS.ANALYZER_RETIREJS_ENABLED, retireJsAnalyzerEnabled);
        getSettings().setStringIfNotNull(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_URL, retireJsUrl);
        getSettings().setBooleanIfNotNull(Settings.KEYS.ANALYZER_RETIREJS_FILTER_NON_VULNERABLE, retirejsFilterNonVulnerable);
        getSettings().setArrayIfNotEmpty(Settings.KEYS.ANALYZER_RETIREJS_FILTERS, retirejsFilters);

        getSettings().setBooleanIfNotNull(Settings.KEYS.ANALYZER_NUSPEC_ENABLED, nuspecAnalyzerEnabled);
        getSettings().setBooleanIfNotNull(Settings.KEYS.ANALYZER_NUGETCONF_ENABLED, nugetconfAnalyzerEnabled);
        getSettings().setBooleanIfNotNull(Settings.KEYS.ANALYZER_CENTRAL_ENABLED, centralAnalyzerEnabled);
        getSettings().setBooleanIfNotNull(Settings.KEYS.ANALYZER_CENTRAL_USE_CACHE, centralAnalyzerUseCache);
        getSettings().setBooleanIfNotNull(Settings.KEYS.ANALYZER_NEXUS_ENABLED, nexusAnalyzerEnabled);
        getSettings().setBooleanIfNotNull(Settings.KEYS.ANALYZER_ARCHIVE_ENABLED, archiveAnalyzerEnabled);
        getSettings().setBooleanIfNotNull(Settings.KEYS.ANALYZER_ASSEMBLY_ENABLED, assemblyAnalyzerEnabled);
        getSettings().setStringIfNotEmpty(Settings.KEYS.ANALYZER_NEXUS_URL, nexusUrl);
        getSettings().setStringIfNotEmpty(Settings.KEYS.ANALYZER_NEXUS_USER, nexusUser);
        getSettings().setStringIfNotEmpty(Settings.KEYS.ANALYZER_NEXUS_PASSWORD, nexusPassword);
        getSettings().setBooleanIfNotNull(Settings.KEYS.ANALYZER_NEXUS_USES_PROXY, nexusUsesProxy);
        getSettings().setStringIfNotEmpty(Settings.KEYS.ADDITIONAL_ZIP_EXTENSIONS, zipExtensions);
        getSettings().setStringIfNotEmpty(Settings.KEYS.ANALYZER_ASSEMBLY_DOTNET_PATH, pathToCore);
        getSettings().setBooleanIfNotNull(Settings.KEYS.ANALYZER_OSSINDEX_ENABLED, ossindexAnalyzerEnabled);
        getSettings().setStringIfNotEmpty(Settings.KEYS.ANALYZER_OSSINDEX_URL, ossindexAnalyzerUrl);
        getSettings().setBooleanIfNotNull(Settings.KEYS.ANALYZER_OSSINDEX_USE_CACHE, ossindexAnalyzerUseCache);
        getSettings().setFloat(Settings.KEYS.JUNIT_FAIL_ON_CVSS, junitFailOnCVSS);
    }

    /**
     * Checks to see if a vulnerability has been identified with a CVSS score
     * that is above the threshold set in the configuration.
     *
     * @param dependencies the list of dependency objects
     * @throws BuildException thrown if a CVSS score is found that is higher
     * than the threshold set
     */
    private void checkForFailure(Dependency[] dependencies) throws BuildException {
        final StringBuilder ids = new StringBuilder();
        for (Dependency d : dependencies) {
            for (Vulnerability v : d.getVulnerabilities()) {
                if ((v.getCvssV2() != null && v.getCvssV2().getScore() >= failBuildOnCVSS)
                        || (v.getCvssV3() != null && v.getCvssV3().getBaseScore() >= failBuildOnCVSS)) {
                    if (ids.length() == 0) {
                        ids.append(v.getName());
                    } else {
                        ids.append(", ").append(v.getName());
                    }
                }
            }
        }
        if (ids.length() > 0) {
            final String msg;
            if (showSummary) {
                msg = String.format("%n%nDependency-Check Failure:%n"
                        + "One or more dependencies were identified with vulnerabilities that have a CVSS score greater than or equal to '%.1f': %s%n"
                        + "See the dependency-check report for more details.%n%n", failBuildOnCVSS, ids.toString());
            } else {
                msg = String.format("%n%nDependency-Check Failure:%n"
                        + "One or more dependencies were identified with vulnerabilities.%n%n"
                        + "See the dependency-check report for more details.%n%n");
            }
            throw new BuildException(msg);
        }
    }

    /**
     * An enumeration of supported report formats: "ALL", "HTML", "XML", "CSV",
     * "JSON", "JUNIT", etc..
     */
    public static class ReportFormats extends EnumeratedAttribute {

        /**
         * Returns the list of values for the report format.
         *
         * @return the list of values for the report format
         */
        @Override
        public String[] getValues() {
            int i = 0;
            final Format[] formats = Format.values();
            final String[] values = new String[formats.length];
            for (Format format : formats) {
                values[i++] = format.name();
            }
            return values;
        }
    }
}
