/*
 * This file is part of dependency-check-maven.
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
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.maven;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL.StandardTypes;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.artifact.versioning.ArtifactVersion;
import org.apache.maven.doxia.sink.Sink;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.License;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.DefaultProjectBuildingRequest;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.ProjectBuildingRequest;
import org.apache.maven.reporting.MavenReport;
import org.apache.maven.reporting.MavenReportException;
import org.apache.maven.settings.Proxy;
import org.apache.maven.settings.Server;
import org.apache.maven.shared.artifact.filter.resolve.PatternInclusionsFilter;
import org.apache.maven.shared.artifact.filter.resolve.TransformableFilter;
import org.apache.maven.shared.transfer.artifact.ArtifactCoordinate;
import org.apache.maven.shared.transfer.artifact.DefaultArtifactCoordinate;
import org.apache.maven.shared.transfer.artifact.TransferUtils;
import org.apache.maven.shared.transfer.artifact.resolve.ArtifactResolver;
import org.apache.maven.shared.transfer.artifact.resolve.ArtifactResolverException;
import org.apache.maven.shared.transfer.artifact.resolve.ArtifactResult;
import org.apache.maven.shared.transfer.dependencies.resolve.DependencyResolver;
import org.apache.maven.shared.transfer.dependencies.resolve.DependencyResolverException;
import org.eclipse.aether.artifact.ArtifactType;
import org.apache.maven.shared.artifact.filter.PatternExcludesArtifactFilter;
import org.apache.maven.shared.dependency.graph.DependencyGraphBuilder;
import org.apache.maven.shared.dependency.graph.DependencyGraphBuilderException;
import org.apache.maven.shared.dependency.graph.DependencyNode;
import org.apache.maven.shared.dependency.graph.filter.ArtifactDependencyNodeFilter;
import org.apache.maven.shared.dependency.graph.internal.DefaultDependencyNode;
import org.apache.maven.shared.model.fileset.FileSet;
import org.apache.maven.shared.model.fileset.util.FileSetManager;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.JarAnalyzer;
import org.owasp.dependencycheck.data.nexus.MavenArtifact;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.exception.DependencyNotFoundException;
import org.owasp.dependencycheck.exception.ExceptionCollection;
import org.owasp.dependencycheck.exception.ReportException;
import org.owasp.dependencycheck.utils.Checksum;
import org.owasp.dependencycheck.utils.CveUrlParser;
import org.owasp.dependencycheck.utils.Filter;
import org.owasp.dependencycheck.utils.Settings;
import org.sonatype.plexus.components.sec.dispatcher.DefaultSecDispatcher;
import org.sonatype.plexus.components.sec.dispatcher.SecDispatcher;
import org.sonatype.plexus.components.sec.dispatcher.SecDispatcherException;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import org.apache.maven.artifact.resolver.filter.ExcludesArtifactFilter;
import org.apache.maven.artifact.versioning.InvalidVersionSpecificationException;
import org.apache.maven.artifact.versioning.Restriction;
import org.apache.maven.artifact.versioning.VersionRange;
import org.apache.maven.shared.dependency.graph.traversal.CollectingDependencyNodeVisitor;

import org.owasp.dependencycheck.agent.DependencyCheckScanAgent;
import org.owasp.dependencycheck.dependency.naming.GenericIdentifier;
import org.owasp.dependencycheck.dependency.naming.Identifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.apache.maven.shared.dependency.graph.traversal.DependencyNodeVisitor;
import org.apache.maven.shared.dependency.graph.traversal.FilteringDependencyNodeVisitor;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.reporting.ReportGenerator;
import org.owasp.dependencycheck.utils.SeverityUtil;
import org.owasp.dependencycheck.xml.pom.Model;
import org.owasp.dependencycheck.xml.pom.PomUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.spi.LocationAwareLogger;

//CSOFF: FileLength
/**
 * @author Jeremy Long
 */
public abstract class BaseDependencyCheckMojo extends AbstractMojo implements MavenReport {

    //<editor-fold defaultstate="collapsed" desc="Private fields">
    /**
     * The properties file location.
     */
    private static final String PROPERTIES_FILE = "mojo.properties";
    /**
     * System specific new line character.
     */
    private static final String NEW_LINE = System.getProperty("line.separator", "\n").intern();
    /**
     * Pattern to include all files in a FileSet.
     */
    private static final String INCLUDE_ALL = "**/*";
    /**
     * A flag indicating whether or not the Maven site is being generated.
     */
    private boolean generatingSite = false;
    /**
     * The configured settings.
     */
    private Settings settings = null;
    /**
     * The list of files that have been scanned.
     */
    private List<File> scannedFiles = new ArrayList<>();
    //</editor-fold>
    // <editor-fold defaultstate="collapsed" desc="Maven bound parameters and components">
    /**
     * Sets whether or not the mojo should fail if an error occurs.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "failOnError", defaultValue = "true", required = true)
    private boolean failOnError;

    /**
     * The Maven Project Object.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "project", required = true, readonly = true)
    private MavenProject project;
    /**
     * List of Maven project of the current build
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(readonly = true, required = true, property = "reactorProjects")
    private List<MavenProject> reactorProjects;
    /**
     * The entry point towards a Maven version independent way of resolving
     * artifacts (handles both Maven 3.0 Sonatype and Maven 3.1+ eclipse Aether
     * implementations).
     */
    @SuppressWarnings("CanBeFinal")
    @Component
    private ArtifactResolver artifactResolver;
    /**
     * The entry point towards a Maven version independent way of resolving
     * dependencies (handles both Maven 3.0 Sonatype and Maven 3.1+ eclipse
     * Aether implementations). Contrary to the ArtifactResolver this resolver
     * also takes into account the additional repositories defined in the
     * dependency-path towards transitive dependencies.
     */
    @SuppressWarnings("CanBeFinal")
    @Component
    private DependencyResolver dependencyResolver;

    /**
     * The Maven Session.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(defaultValue = "${session}", readonly = true, required = true)
    private MavenSession session;

    /**
     * Component within Maven to build the dependency graph.
     */
    @Component
    private DependencyGraphBuilder dependencyGraphBuilder;

    /**
     * The output directory. This generally maps to "target".
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(defaultValue = "${project.build.directory}", required = true, property = "odc.outputDirectory")
    private File outputDirectory;
    /**
     * This is a reference to the &gt;reporting&lt; sections
     * <code>outputDirectory</code>. This cannot be configured in the
     * dependency-check mojo directly. This generally maps to "target/site".
     */
    @Parameter(property = "project.reporting.outputDirectory", readonly = true)
    private File reportOutputDirectory;
    /**
     * Specifies if the build should be failed if a CVSS score above a specified
     * level is identified. The default is 11 which means since the CVSS scores
     * are 0-10, by default the build will never fail.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "failBuildOnCVSS", defaultValue = "11", required = true)
    private float failBuildOnCVSS = 11f;
    /**
     * Specifies the CVSS score that is considered a "test" failure when
     * generating a jUnit style report. The default value is 0 - all
     * vulnerabilities are considered a failure.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "junitFailOnCVSS", defaultValue = "0", required = true)
    private float junitFailOnCVSS = 0;
    /**
     * Fail the build if any dependency has a vulnerability listed.
     *
     * @deprecated use {@link BaseDependencyCheckMojo#failBuildOnCVSS} with a
     * value of 0 instead
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "failBuildOnAnyVulnerability", defaultValue = "false", required = true)
    @Deprecated
    private boolean failBuildOnAnyVulnerability = false;
    /**
     * Sets whether auto-updating of the NVD CVE/CPE data is enabled. It is not
     * recommended that this be turned to false. Default is true.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "autoUpdate")
    private Boolean autoUpdate;
    /**
     * Sets whether Experimental analyzers are enabled. Default is false.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "enableExperimental")
    private Boolean enableExperimental;
    /**
     * Sets whether retired analyzers are enabled. Default is false.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "enableRetired")
    private Boolean enableRetired;
    /**
     * Sets whether the Golang Dependency analyzer is enabled. Default is true.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "golangDepEnabled")
    private Boolean golangDepEnabled;
    /**
     * Sets whether Golang Module Analyzer is enabled; this requires `go` to be
     * installed. Default is true.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "golangModEnabled")
    private Boolean golangModEnabled;
    /**
     * Sets the path to `go`.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "pathToGo")
    private String pathToGo;
    /**
     * Sets the path to `yarn`.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "pathToYarn")
    private String pathToYarn;
    /**
     * Sets the path to `pnpm`.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "pathToPnpm")
    private String pathToPnpm;
    /**
     * Use pom dependency information for snapshot dependencies that are part of
     * the Maven reactor while aggregate scanning a multi-module project.
     */
    @Parameter(property = "dependency-check.virtualSnapshotsFromReactor", defaultValue = "true")
    private Boolean virtualSnapshotsFromReactor;
    /**
     * The report format to be generated (HTML, XML, JUNIT, CSV, JSON, SARIF,
     * ALL). Multiple formats can be selected using a comma delineated list.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "format", defaultValue = "HTML", required = true)
    private String format = "HTML";

    /**
     * Whether or not the XML and JSON report formats should be pretty printed.
     * The default is false.
     */
    @Parameter(property = "prettyPrint")
    private Boolean prettyPrint;
    /**
     * The report format to be generated (HTML, XML, JUNIT, CSV, JSON, SARIF,
     * ALL). Multiple formats can be selected using a comma delineated list.
     */
    @Parameter(property = "formats", required = true)
    private String[] formats;
    /**
     * The Maven settings.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "mavenSettings", defaultValue = "${settings}")
    private org.apache.maven.settings.Settings mavenSettings;

    /**
     * The maven settings proxy id.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "mavenSettingsProxyId")
    private String mavenSettingsProxyId;

    /**
     * The Connection Timeout.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "connectionTimeout")
    private String connectionTimeout;
    /**
     * Sets whether dependency-check should check if there is a new version
     * available.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "versionCheckEnabled", defaultValue = "true")
    private boolean versionCheckEnabled;
    /**
     * The paths to the suppression files. The parameter value can be a local
     * file path, a URL to a suppression file, or even a reference to a file on
     * the class path (see
     * https://github.com/jeremylong/DependencyCheck/issues/1878#issuecomment-487533799)
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "suppressionFiles")
    private String[] suppressionFiles;
    /**
     * The paths to the suppression file. The parameter value can be a local
     * file path, a URL to a suppression file, or even a reference to a file on
     * the class path (see
     * https://github.com/jeremylong/DependencyCheck/issues/1878#issuecomment-487533799)
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "suppressionFile")
    private String suppressionFile;
    /**
     * The username used when connecting to the suppressionFiles.
     */
    @Parameter(property = "suppressionFileUser")
    private String suppressionFileUser;
    /**
     * The password used when connecting to the suppressionFiles.
     */
    @Parameter(property = "suppressionFilePassword")
    private String suppressionFilePassword;
    /**
     * The server id in the settings.xml; used to retrieve encrypted passwords
     * from the settings.xml for suppressionFile(s).
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "suppressionFileServerId")
    private String suppressionFileServerId;
    /**
     * The path to the hints file.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "hintsFile")
    private String hintsFile;

    /**
     * Flag indicating whether or not to show a summary in the output.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "showSummary", defaultValue = "true")
    private boolean showSummary = true;

    /**
     * Whether or not the Jar Analyzer is enabled.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "jarAnalyzerEnabled")
    private Boolean jarAnalyzerEnabled;

    /**
     * Whether or not the Archive Analyzer is enabled.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "archiveAnalyzerEnabled")
    private Boolean archiveAnalyzerEnabled;

    /**
     * Sets whether the Python Distribution Analyzer will be used.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "pyDistributionAnalyzerEnabled")
    private Boolean pyDistributionAnalyzerEnabled;
    /**
     * Sets whether the Python Package Analyzer will be used.
     */
    @Parameter(property = "pyPackageAnalyzerEnabled")
    private Boolean pyPackageAnalyzerEnabled;
    /**
     * Sets whether the Ruby Gemspec Analyzer will be used.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "rubygemsAnalyzerEnabled")
    private Boolean rubygemsAnalyzerEnabled;
    /**
     * Sets whether or not the openssl Analyzer should be used.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "opensslAnalyzerEnabled")
    private Boolean opensslAnalyzerEnabled;
    /**
     * Sets whether or not the CMake Analyzer should be used.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "cmakeAnalyzerEnabled")
    private Boolean cmakeAnalyzerEnabled;
    /**
     * Sets whether or not the autoconf Analyzer should be used.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "autoconfAnalyzerEnabled")
    private Boolean autoconfAnalyzerEnabled;
    /**
     * Sets whether or not the pip Analyzer should be used.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "pipAnalyzerEnabled")
    private Boolean pipAnalyzerEnabled;
    /**
     * Sets whether or not the pipfile Analyzer should be used.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "pipfileAnalyzerEnabled")
    private Boolean pipfileAnalyzerEnabled;
    /**
     * Sets whether or not the PHP Composer Lock File Analyzer should be used.
     */
    @Parameter(property = "composerAnalyzerEnabled")
    private Boolean composerAnalyzerEnabled;
    /**
     * Whether or not the Perl CPAN File Analyzer is enabled.
     */
    @Parameter(property = "cpanfileAnalyzerEnabled")
    private Boolean cpanfileAnalyzerEnabled;
    /**
     * Sets whether or not the Node.js Analyzer should be used.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nodeAnalyzerEnabled")
    private Boolean nodeAnalyzerEnabled;
    /**
     * Sets whether or not the Node Audit Analyzer should be used.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nodeAuditAnalyzerEnabled")
    private Boolean nodeAuditAnalyzerEnabled;

    /**
     * Sets whether or not the Yarn Audit Analyzer should be used.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "yarnAuditAnalyzerEnabled")
    private Boolean yarnAuditAnalyzerEnabled;

    /**
     * Sets whether or not the Pnpm Audit Analyzer should be used.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "pnpmAuditAnalyzerEnabled")
    private Boolean pnpmAuditAnalyzerEnabled;

    /**
     * Sets whether or not the Node Audit Analyzer should use a local cache.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nodeAuditAnalyzerUseCache")
    private Boolean nodeAuditAnalyzerUseCache;
    /**
     * Sets whether or not the Node Audit Analyzer should skip devDependencies.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nodeAuditSkipDevDependencies")
    private Boolean nodeAuditSkipDevDependencies;
    /**
     * Sets whether or not the Node Audit Analyzer should skip devDependencies.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nodePackageSkipDevDependencies")
    private Boolean nodePackageSkipDevDependencies;
    /**
     * Sets whether or not the Retirejs Analyzer should be used.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "retireJsAnalyzerEnabled")
    private Boolean retireJsAnalyzerEnabled;
    /**
     * The Retire JS repository URL.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "retireJsUrl")
    private String retireJsUrl;
    /**
     * Whether the Retire JS repository will be updated regardless of the
     * `autoupdate` settings.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "retireJsForceUpdate")
    private Boolean retireJsForceUpdate;
    /**
     * Whether or not the .NET Assembly Analyzer is enabled.
     */
    @Parameter(property = "assemblyAnalyzerEnabled")
    private Boolean assemblyAnalyzerEnabled;
    /**
     * Whether or not the MS Build Analyzer is enabled.
     */
    @Parameter(property = "msbuildAnalyzerEnabled")
    private Boolean msbuildAnalyzerEnabled;
    /**
     * Whether or not the .NET Nuspec Analyzer is enabled.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nuspecAnalyzerEnabled")
    private Boolean nuspecAnalyzerEnabled;

    /**
     * Whether or not the .NET packages.config Analyzer is enabled.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nugetconfAnalyzerEnabled")
    private Boolean nugetconfAnalyzerEnabled;

    /**
     * Whether or not the Central Analyzer is enabled.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "centralAnalyzerEnabled")
    private Boolean centralAnalyzerEnabled;

    /**
     * Whether or not the Central Analyzer should use a local cache.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "centralAnalyzerUseCache")
    private Boolean centralAnalyzerUseCache;

    /**
     * Whether or not the Artifactory Analyzer is enabled.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "artifactoryAnalyzerEnabled")
    private Boolean artifactoryAnalyzerEnabled;
    /**
     * The serverId inside the settings.xml containing the username and token to
     * access artifactory
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "artifactoryAnalyzerServerId")
    private String artifactoryAnalyzerServerId;
    /**
     * The username (only used with API token) to connect to Artifactory
     * instance
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "artifactoryAnalyzerUsername")
    private String artifactoryAnalyzerUsername;
    /**
     * The API token to connect to Artifactory instance
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "artifactoryAnalyzerApiToken")
    private String artifactoryAnalyzerApiToken;
    /**
     * The bearer token to connect to Artifactory instance
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "artifactoryAnalyzerBearerToken")
    private String artifactoryAnalyzerBearerToken;
    /**
     * The Artifactory URL for the Artifactory analyzer.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "artifactoryAnalyzerUrl")
    private String artifactoryAnalyzerUrl;
    /**
     * Whether Artifactory should be accessed through a proxy or not
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "artifactoryAnalyzerUseProxy")
    private Boolean artifactoryAnalyzerUseProxy;
    /**
     * Whether the Artifactory analyzer should be run in parallel or not.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "artifactoryAnalyzerParallelAnalysis", defaultValue = "true")
    private Boolean artifactoryAnalyzerParallelAnalysis;
    /**
     * Whether or not the Nexus Analyzer is enabled.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nexusAnalyzerEnabled")
    private Boolean nexusAnalyzerEnabled;

    /**
     * Whether or not the Sonatype OSS Index analyzer is enabled.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "ossindexAnalyzerEnabled")
    private Boolean ossindexAnalyzerEnabled;
    /**
     * Whether or not the Sonatype OSS Index analyzer is enabled.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "ossindexAnalyzerUseCache")
    private Boolean ossindexAnalyzerUseCache;
    /**
     * URL of the Sonatype OSS Index service.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "ossindexAnalyzerUrl")
    private String ossindexAnalyzerUrl;

    /**
     * The id of a server defined in the settings.xml that configures the
     * credentials (username and password) for a OSS Index service.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "ossIndexServerId")
    private String ossIndexServerId;

    /**
     * Whether or not the Elixir Mix Audit Analyzer is enabled.
     */
    @Parameter(property = "mixAuditAnalyzerEnabled")
    private Boolean mixAuditAnalyzerEnabled;

    /**
     * Sets the path for the mix_audit binary.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "mixAuditPath")
    private String mixAuditPath;

    /**
     * Whether or not the Ruby Bundle Audit Analyzer is enabled.
     */
    @Parameter(property = "bundleAuditAnalyzerEnabled")
    private Boolean bundleAuditAnalyzerEnabled;

    /**
     * Sets the path for the bundle-audit binary.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "bundleAuditPath")
    private String bundleAuditPath;

    /**
     * Sets the path for the working directory that the bundle-audit binary
     * should be executed from.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "bundleAuditWorkingDirectory")
    private String bundleAuditWorkingDirectory;

    /**
     * Whether or not the CocoaPods Analyzer is enabled.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "cocoapodsAnalyzerEnabled")
    private Boolean cocoapodsAnalyzerEnabled;

    /**
     * Whether or not the Swift package Analyzer is enabled.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "swiftPackageManagerAnalyzerEnabled")
    private Boolean swiftPackageManagerAnalyzerEnabled;
    /**
     * Whether or not the Swift package resolved Analyzer is enabled.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "swiftPackageResolvedAnalyzerEnabled")
    private Boolean swiftPackageResolvedAnalyzerEnabled;
    /**
     * The URL of a Nexus server's REST API end point
     * (http://domain/nexus/service/local).
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nexusUrl")
    private String nexusUrl;
    /**
     * The id of a server defined in the settings.xml that configures the
     * credentials (username and password) for a Nexus server's REST API end
     * point. When not specified the communication with the Nexus server's REST
     * API will be unauthenticated.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nexusServerId")
    private String nexusServerId;
    /**
     * Whether or not the configured proxy is used to connect to Nexus.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nexusUsesProxy")
    private Boolean nexusUsesProxy;
    /**
     * The database connection string.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "connectionString")
    private String connectionString;

    /**
     * The database driver name. An example would be org.h2.Driver.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "databaseDriverName")
    private String databaseDriverName;
    /**
     * The path to the database driver if it is not on the class path.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "databaseDriverPath")
    private String databaseDriverPath;
    /**
     * The server id in the settings.xml; used to retrieve encrypted passwords
     * from the settings.xml.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "serverId")
    private String serverId;
    /**
     * A reference to the settings.xml settings.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(defaultValue = "${settings}", readonly = true, required = true)
    private org.apache.maven.settings.Settings settingsXml;
    /**
     * The security dispatcher that can decrypt passwords in the settings.xml.
     */
    @Component(role = SecDispatcher.class, hint = "default")
    private SecDispatcher securityDispatcher;
    /**
     * The database user name.
     */
    @Parameter(property = "databaseUser")
    private String databaseUser;
    /**
     * The password to use when connecting to the database.
     */
    @Parameter(property = "databasePassword")
    private String databasePassword;
    /**
     * A comma-separated list of file extensions to add to analysis next to jar,
     * zip, ....
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "zipExtensions")
    private String zipExtensions;
    /**
     * Skip Dependency Check altogether.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "dependency-check.skip", defaultValue = "false")
    private boolean skip = false;
    /**
     * Skip Analysis for Test Scope Dependencies.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "skipTestScope", defaultValue = "true")
    private boolean skipTestScope = true;
    /**
     * Skip Analysis for Runtime Scope Dependencies.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "skipRuntimeScope", defaultValue = "false")
    private boolean skipRuntimeScope = false;
    /**
     * Skip Analysis for Provided Scope Dependencies.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "skipProvidedScope", defaultValue = "false")
    private boolean skipProvidedScope = false;

    /**
     * Skip Analysis for System Scope Dependencies.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "skipSystemScope", defaultValue = "false")
    private boolean skipSystemScope = false;

    /**
     * Skip Analysis for dependencyManagement section.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "skipDependencyManagement", defaultValue = "true")
    private boolean skipDependencyManagement = true;

    /**
     * Skip analysis for dependencies which type matches this regular
     * expression. This filters on the `type` of dependency as defined in the
     * dependency section: jar, pom, test-jar, etc.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "skipArtifactType")
    private String skipArtifactType;

    /**
     * The data directory, hold DC SQL DB.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "dataDirectory")
    private String dataDirectory;

    /**
     * The name of the DC DB.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "dbFilename")
    private String dbFilename;

    /**
     * Data Mirror URL for CVE 1.2.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "cveUrlModified")
    private String cveUrlModified;
    /**
     * Base Data Mirror URL for CVE 1.2.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "cveUrlBase")
    private String cveUrlBase;
    /**
     * The wait timeout between downloading from the NVD.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "cveWaitTime")
    private String cveWaitTime;
    /**
     * The username to use when connecting to the CVE-URL.
     */
    @Parameter(property = "cveUser")
    private String cveUser;
    /**
     * The password to authenticate to the CVE-URL.
     */
    @Parameter(property = "cvePassword")
    private String cvePassword;
    /**
     * The server id in the settings.xml; used to retrieve encrypted passwords
     * from the settings.xml for cve-URLs.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "cveServerId")
    private String cveServerId;
    /**
     * Optionally skip excessive CVE update checks for a designated duration in
     * hours.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "cveValidForHours")
    private Integer cveValidForHours;

    /**
     * Specify the first year of NVD CVE data to download; default is 2002.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "cveStartYear")
    private Integer cveStartYear;

    /**
     * The path to dotnet core.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "pathToCore")
    private String pathToCore;

    /**
     * The RetireJS Analyzer configuration:
     * <pre>
     *   filters: an array of filter patterns that are used to exclude JS files that contain a match
     *   filterNonVulnerable: a boolean that when true will remove non-vulnerable JS from the report
     *
     * Example:
     *   &lt;retirejs&gt;
     *     &lt;filters&gt;
     *       &lt;filter&gt;copyright 2018\(c\) Jeremy Long&lt;/filter&gt;
     *     &lt;/filters&gt;
     *     &lt;filterNonVulnerable&gt;true&lt;/filterNonVulnerable&gt;
     *   &lt;/retirejs&gt;
     * </pre>
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "retirejs")
    private Retirejs retirejs;

    /**
     * The list of artifacts (and their transitive dependencies) to exclude from
     * the check.
     */
    @Parameter
    private List<String> excludes;

    /**
     * The artifact scope filter.
     */
    private Filter<String> artifactScopeExcluded;

    /**
     * Filter for artifact type.
     */
    private Filter<String> artifactTypeExcluded;

    /**
     * An collection of <code>fileSet</code>s that specify additional files
     * and/or directories (from the basedir) to analyze as part of the scan. If
     * not specified, defaults to Maven conventions of: src/main/resources,
     * src/main/filters, and src/main/webapp. Note, this cannot be set via the
     * command line - use `scanDirectory` instead.
     */
    @Parameter
    private List<FileSet> scanSet;
    /**
     * A list of directories to scan. Note, this should only be used via the
     * command line - if configuring the directories to scan consider using the
     * `scanSet` instead.
     */
    @Parameter(property = "scanDirectory")
    private List<String> scanDirectory;

    // </editor-fold>
    //<editor-fold defaultstate="collapsed" desc="Base Maven implementation">
    /**
     * Determines if the groupId, artifactId, and version of the Maven
     * dependency and artifact match.
     *
     * @param d the Maven dependency
     * @param a the Maven artifact
     * @return true if the groupId, artifactId, and version match
     */
    private static boolean artifactsMatch(org.apache.maven.model.Dependency d, Artifact a) {
        return isEqualOrNull(a.getArtifactId(), d.getArtifactId())
                && isEqualOrNull(a.getGroupId(), d.getGroupId())
                && isEqualOrNull(a.getVersion(), d.getVersion());
    }

    /**
     * Compares two strings for equality; if both strings are null they are
     * considered equal.
     *
     * @param left the first string to compare
     * @param right the second string to compare
     * @return true if the strings are equal or if they are both null; otherwise
     * false.
     */
    private static boolean isEqualOrNull(String left, String right) {
        return (left != null && left.equals(right)) || (left == null && right == null);
    }

    /**
     * Executes dependency-check.
     *
     * @throws MojoExecutionException thrown if there is an exception executing
     * the mojo
     * @throws MojoFailureException thrown if dependency-check failed the build
     */
    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        generatingSite = false;
        final boolean shouldSkip = Boolean.parseBoolean(System.getProperty("dependency-check.skip", Boolean.toString(skip)));
        if (shouldSkip) {
            getLog().info("Skipping " + getName(Locale.US));
        } else {
            project.setContextValue("dependency-check-output-dir", this.outputDirectory);
            runCheck();
        }
    }

    /**
     * Generates the Dependency-Check Site Report.
     *
     * @param sink the sink to write the report to
     * @param locale the locale to use when generating the report
     * @throws MavenReportException if a maven report exception occurs
     * @deprecated use
     * {@link #generate(org.apache.maven.doxia.sink.Sink, java.util.Locale)}
     * instead.
     */
    @Override
    @Deprecated
    public final void generate(@SuppressWarnings("deprecation") org.codehaus.doxia.sink.Sink sink, Locale locale) throws MavenReportException {
        generate((Sink) sink, locale);
    }

    /**
     * Returns true if the Maven site is being generated.
     *
     * @return true if the Maven site is being generated
     */
    protected boolean isGeneratingSite() {
        return generatingSite;
    }

    /**
     * Returns the connection string.
     *
     * @return the connection string
     */
    protected String getConnectionString() {
        return connectionString;
    }

    /**
     * Returns if the mojo should fail the build if an exception occurs.
     *
     * @return whether or not the mojo should fail the build
     */
    protected boolean isFailOnError() {
        return failOnError;
    }

    /**
     * Generates the Dependency-Check Site Report.
     *
     * @param sink the sink to write the report to
     * @param locale the locale to use when generating the report
     * @throws MavenReportException if a maven report exception occurs
     */
    public void generate(Sink sink, Locale locale) throws MavenReportException {
        final boolean shouldSkip = Boolean.parseBoolean(System.getProperty("dependency-check.skip", Boolean.toString(skip)));
        if (shouldSkip) {
            getLog().info("Skipping report generation " + getName(Locale.US));
            return;
        }

        generatingSite = true;
        project.setContextValue("dependency-check-output-dir", getReportOutputDirectory());
        try {
            runCheck();
        } catch (MojoExecutionException ex) {
            throw new MavenReportException(ex.getMessage(), ex);
        } catch (MojoFailureException ex) {
            getLog().warn("Vulnerabilities were identifies that exceed the CVSS threshold for failing the build");
        }
    }

    /**
     * Returns the correct output directory depending on if a site is being
     * executed or not.
     *
     * @return the directory to write the report(s)
     * @throws MojoExecutionException thrown if there is an error loading the
     * file path
     */
    protected File getCorrectOutputDirectory() throws MojoExecutionException {
        return getCorrectOutputDirectory(this.project);
    }

    /**
     * Returns the correct output directory depending on if a site is being
     * executed or not.
     *
     * @param current the Maven project to get the output directory from
     * @return the directory to write the report(s)
     */
    protected File getCorrectOutputDirectory(MavenProject current) {
        final Object obj = current.getContextValue("dependency-check-output-dir");
        if (obj != null && obj instanceof File) {
            return (File) obj;
        }
        //else we guess
        File target = new File(current.getBuild().getDirectory());
        if (target.getParentFile() != null && "target".equals(target.getParentFile().getName())) {
            target = target.getParentFile();
        }
        return target;
    }

    /**
     * Scans the project's artifacts and adds them to the engine's dependency
     * list.
     *
     * @param project the project to scan the dependencies of
     * @param engine the engine to use to scan the dependencies
     * @return a collection of exceptions that may have occurred while resolving
     * and scanning the dependencies
     */
    protected ExceptionCollection scanArtifacts(MavenProject project, Engine engine) {
        return scanArtifacts(project, engine, false);
    }

    /**
     * Scans the project's artifacts and adds them to the engine's dependency
     * list.
     *
     * @param project the project to scan the dependencies of
     * @param engine the engine to use to scan the dependencies
     * @param aggregate whether the scan is part of an aggregate build
     * @return a collection of exceptions that may have occurred while resolving
     * and scanning the dependencies
     */
    protected ExceptionCollection scanArtifacts(MavenProject project, Engine engine, boolean aggregate) {
        try {
            final List<String> filterItems = Collections.singletonList(String.format("%s:%s", project.getGroupId(), project.getArtifactId()));
            final ProjectBuildingRequest buildingRequest = newResolveArtifactProjectBuildingRequest(project);
            //For some reason the filter does not filter out the project being analyzed
            //if we pass in the filter below instead of null to the dependencyGraphBuilder
            final DependencyNode dn = dependencyGraphBuilder.buildDependencyGraph(buildingRequest, null, reactorProjects);

            final CollectingDependencyNodeVisitor collectorVisitor = new CollectingDependencyNodeVisitor();
            // exclude artifact by pattern and its dependencies
            final DependencyNodeVisitor transitiveFilterVisitor = new FilteringDependencyTransitiveNodeVisitor(collectorVisitor,
                    new ArtifactDependencyNodeFilter(new PatternExcludesArtifactFilter(getExcludes())));
            // exclude exact artifact but not its dependencies, this filter must be appied on the root for first otherwise
            // in case the exclude has the same groupId of the current bundle its direct dependencies are not visited
            final DependencyNodeVisitor artifactFilter = new FilteringDependencyNodeVisitor(transitiveFilterVisitor,
                    new ArtifactDependencyNodeFilter(new ExcludesArtifactFilter(filterItems)));
            dn.accept(artifactFilter);

            //collect dependencies with the filter - see comment above.
            final List<DependencyNode> nodes = new ArrayList<>(collectorVisitor.getNodes());

            return collectDependencies(engine, project, nodes, buildingRequest, aggregate);
        } catch (DependencyGraphBuilderException ex) {
            final String msg = String.format("Unable to build dependency graph on project %s", project.getName());
            getLog().debug(msg, ex);
            return new ExceptionCollection(ex);
        }
    }

    /**
     * Converts the dependency to a dependency node object.
     *
     * @param nodes the list of dependency nodes
     * @param buildingRequest the Maven project building request
     * @param parent the parent node
     * @param dependency the dependency to convert
     * @return the resulting dependency node
     * @throws ArtifactResolverException thrown if the artifact could not be
     * retrieved
     */
    private DependencyNode toDependencyNode(List<DependencyNode> nodes, ProjectBuildingRequest buildingRequest,
            DependencyNode parent, org.apache.maven.model.Dependency dependency) throws ArtifactResolverException {

        final DefaultArtifactCoordinate coordinate = new DefaultArtifactCoordinate();

        coordinate.setGroupId(dependency.getGroupId());
        coordinate.setArtifactId(dependency.getArtifactId());
        String version = null;
        final VersionRange vr;
        try {
            vr = VersionRange.createFromVersionSpec(dependency.getVersion());
        } catch (InvalidVersionSpecificationException ex) {
            throw new ArtifactResolverException("Invalid version specification: "
                    + dependency.getGroupId() + ":"
                    + dependency.getArtifactId() + ":"
                    + dependency.getVersion(), ex);
        }
        if (vr.hasRestrictions()) {
            version = findVersion(nodes, dependency.getGroupId(), dependency.getArtifactId());
            if (version == null) {
                //TODO - this still may fail if the restriction is not a valid version number (i.e. only 2.9 instead of 2.9.1)
                //need to get available versions and filter on the restrictions.
                if (vr.getRecommendedVersion() != null) {
                    version = vr.getRecommendedVersion().toString();
                } else if (vr.hasRestrictions()) {
                    for (Restriction restriction : vr.getRestrictions()) {
                        if (restriction.getLowerBound() != null) {
                            version = restriction.getLowerBound().toString();
                        }
                        if (restriction.getUpperBound() != null) {
                            version = restriction.getUpperBound().toString();
                        }
                    }
                } else {
                    version = vr.toString();
                }
            }
        }
        if (version == null) {
            version = dependency.getVersion();
        }
        coordinate.setVersion(version);

        final ArtifactType type = session.getRepositorySession().getArtifactTypeRegistry().get(dependency.getType());
        coordinate.setExtension(type.getExtension());
        coordinate.setClassifier((null == dependency.getClassifier() || dependency.getClassifier().isEmpty())
                ? type.getClassifier() : dependency.getClassifier());
        final Artifact artifact = artifactResolver.resolveArtifact(buildingRequest, coordinate).getArtifact();
        artifact.setScope(dependency.getScope());
        return new DefaultDependencyNode(parent, artifact, dependency.getVersion(), dependency.getScope(), null);
    }

    /**
     * Returns the version from the list of nodes that match the given groupId
     * and artifactID.
     *
     * @param nodes the nodes to search
     * @param groupId the group id to find
     * @param artifactId the artifact id to find
     * @return the version from the list of nodes that match the given groupId
     * and artifactID; otherwise <code>null</code> is returned
     */
    private String findVersion(List<DependencyNode> nodes, String groupId, String artifactId) {
        final Optional<DependencyNode> f = nodes.stream().filter(p
                -> groupId.equals(p.getArtifact().getGroupId())
                && artifactId.equals(p.getArtifact().getArtifactId())).findFirst();
        if (f.isPresent()) {
            return f.get().getArtifact().getVersion();
        }
        return null;
    }

    /**
     * Collect dependencies from the dependency management section.
     *
     * @param engine reference to the ODC engine
     * @param buildingRequest the Maven project building request
     * @param project the project being analyzed
     * @param nodes the list of dependency nodes
     * @param aggregate whether or not this is an aggregate analysis
     * @return a collection of exceptions if any occurred; otherwise
     * <code>null</code>
     */
    private ExceptionCollection collectDependencyManagementDependencies(Engine engine, ProjectBuildingRequest buildingRequest,
            MavenProject project, List<DependencyNode> nodes, boolean aggregate) {
        if (skipDependencyManagement || project.getDependencyManagement() == null) {
            return null;
        }

        ExceptionCollection exCol = null;
        for (org.apache.maven.model.Dependency dependency : project.getDependencyManagement().getDependencies()) {
            try {
                nodes.add(toDependencyNode(nodes, buildingRequest, null, dependency));
            } catch (ArtifactResolverException ex) {
                getLog().debug(String.format("Aggregate : %s", aggregate));
                boolean addException = true;
                //CSOFF: EmptyBlock
                if (!aggregate) {
                    // do nothing, exception is to be reported
                } else if (addReactorDependency(engine,
                        new DefaultArtifact(dependency.getGroupId(), dependency.getArtifactId(),
                                dependency.getVersion(), dependency.getScope(), dependency.getType(), dependency.getClassifier(),
                                new DefaultArtifactHandler()))) {
                    addException = false;
                }
                //CSON: EmptyBlock
                if (addException) {
                    if (exCol == null) {
                        exCol = new ExceptionCollection();
                    }
                    exCol.addException(ex);
                }
            }
        }
        return exCol;
    }

    /**
     * Resolves the projects artifacts using Aether and scans the resulting
     * dependencies.
     *
     * @param engine the core dependency-check engine
     * @param project the project being scanned
     * @param nodes the list of dependency nodes, generally obtained via the
     * DependencyGraphBuilder
     * @param buildingRequest the Maven project building request
     * @param aggregate whether the scan is part of an aggregate build
     * @return a collection of exceptions that may have occurred while resolving
     * and scanning the dependencies
     */
    //CSOFF: OperatorWrap
    private ExceptionCollection collectMavenDependencies(Engine engine, MavenProject project,
            List<DependencyNode> nodes, ProjectBuildingRequest buildingRequest, boolean aggregate) {

        ExceptionCollection exCol = collectDependencyManagementDependencies(engine, buildingRequest, project, nodes, aggregate);

        for (DependencyNode dependencyNode : nodes) {
            if (artifactScopeExcluded.passes(dependencyNode.getArtifact().getScope())
                    || artifactTypeExcluded.passes(dependencyNode.getArtifact().getType())) {
                continue;
            }

            boolean isResolved = false;
            File artifactFile = null;
            String artifactId = null;
            String groupId = null;
            String version = null;
            List<ArtifactVersion> availableVersions = null;
            if (org.apache.maven.artifact.Artifact.SCOPE_SYSTEM.equals(dependencyNode.getArtifact().getScope())) {
                final Artifact a = dependencyNode.getArtifact();
                if (a.isResolved() && a.getFile().isFile()) {
                    artifactFile = a.getFile();
                    isResolved = artifactFile.isFile();
                    groupId = a.getGroupId();
                    artifactId = a.getArtifactId();
                    version = a.getVersion();
                    availableVersions = a.getAvailableVersions();
                } else {
                    for (org.apache.maven.model.Dependency d : project.getDependencies()) {
                        if (d.getSystemPath() != null && artifactsMatch(d, a)) {
                            artifactFile = new File(d.getSystemPath());
                            isResolved = artifactFile.isFile();
                            groupId = a.getGroupId();
                            artifactId = a.getArtifactId();
                            version = a.getVersion();
                            availableVersions = a.getAvailableVersions();
                            break;
                        }
                    }
                }
                if (!isResolved) {
                    getLog().error("Unable to resolve system scoped dependency: " + dependencyNode.toNodeString());
                    if (exCol == null) {
                        exCol = new ExceptionCollection();
                    }
                    exCol.addException(new DependencyNotFoundException("Unable to resolve system scoped dependency: "
                            + dependencyNode.toNodeString()));
                }
            } else {
                final Artifact dependencyArtifact = dependencyNode.getArtifact();
                Artifact result;
                if (dependencyArtifact.isResolved()) {
                    //All transitive dependencies, excluding reactor and dependencyManagement artifacts should
                    //have been resolved by Maven prior to invoking the plugin - resolving the dependencies
                    //manually is unnecessary, and does not work in some cases (issue-1751)
                    getLog().debug(String.format("Skipping artifact %s, already resolved", dependencyArtifact.getArtifactId()));
                    result = dependencyArtifact;
                } else {
                    final ArtifactCoordinate coordinate = TransferUtils.toArtifactCoordinate(dependencyNode.getArtifact());
                    try {
                        final List<org.apache.maven.model.Dependency> dependencies = project.getDependencies();
                        final List<org.apache.maven.model.Dependency> managedDependencies
                                = project.getDependencyManagement() == null ? null : project.getDependencyManagement().getDependencies();
                        if (coordinate.getClassifier() != null) {
                            // This would trigger NPE when using the filter - MSHARED-998
                            getLog().debug("Expensive lookup as workaround for MSHARED-998 for " + coordinate);
                            try {
                                final Iterable<ArtifactResult> allDeps
                                        = dependencyResolver.resolveDependencies(buildingRequest, dependencies, managedDependencies,
                                                                                 null);
                                result = findClassifierArtifactInAllDeps(allDeps, coordinate, project);
                            } catch (DependencyResolverException dre) {
                                result = Mshared998Util.findArtifactInAetherDREResult(dre, coordinate);
                                if (result == null) {
                                    throw new DependencyNotFoundException(
                                            String.format("Failed to resolve dependency %s with dependencyResolver for "
                                                          + "project-artifact %s", coordinate, project.getArtifactId()),
                                            dre);
                                }
                            }
                        } else {
                            final String versionlessFilter =
                                    new StringBuilder(coordinate.getGroupId()).append(':').append(coordinate.getArtifactId()).append(':').append(coordinate.getExtension()).toString();
                            final TransformableFilter filter = new PatternInclusionsFilter(
                                    Collections.singletonList(versionlessFilter));
                            final Iterable<ArtifactResult> singleResult
                                    = dependencyResolver.resolveDependencies(buildingRequest, dependencies, managedDependencies,
                                            filter);

                            if (singleResult.iterator().hasNext()) {
                                final ArtifactResult first = singleResult.iterator().next();
                                result = first.getArtifact();
                            } else {
                                throw new DependencyNotFoundException(String.format("Failed to resolve dependency %s with "
                                        + "dependencyResolver for project-artifact %s", coordinate, project.getArtifactId()));
                            }
                        }
                    } catch (DependencyNotFoundException | DependencyResolverException ex) {
                        getLog().debug(String.format("Aggregate : %s", aggregate));
                        boolean addException = true;
                        //CSOFF: EmptyBlock
                        if (!aggregate) {
                            // do nothing - the exception is to be reported
                        } else if (addReactorDependency(engine, dependencyNode.getArtifact())) {
                            // successfully resolved as a reactor dependency - swallow the exception
                            addException = false;
                        }
                        if (addException) {
                            if (exCol == null) {
                                exCol = new ExceptionCollection();
                            }
                            exCol.addException(ex);
                        }
                        continue;
                    }
                }
                if (aggregate && virtualSnapshotsFromReactor
                        && dependencyNode.getArtifact().isSnapshot()
                        && addSnapshotReactorDependency(engine, dependencyNode.getArtifact())) {
                    continue;
                }
                isResolved = result.isResolved();
                artifactFile = result.getFile();
                groupId = result.getGroupId();
                artifactId = result.getArtifactId();
                version = result.getVersion();
                availableVersions = result.getAvailableVersions();
            }
            if (isResolved && artifactFile != null) {
                final List<Dependency> deps = engine.scan(artifactFile.getAbsoluteFile(),
                        createProjectReferenceName(project, dependencyNode));
                if (deps != null) {
                    scannedFiles.add(artifactFile);
                    Dependency d = null;
                    if (deps.size() == 1) {
                        d = deps.get(0);
                    } else {
                        for (Dependency possible : deps) {
                            if (artifactFile.getAbsoluteFile().equals(possible.getActualFile())) {
                                d = possible;
                                break;
                            }
                        }
                    }
                    if (d != null) {
                        final MavenArtifact ma = new MavenArtifact(groupId, artifactId, version);
                        d.addAsEvidence("pom", ma, Confidence.HIGHEST);
                        if (availableVersions != null) {
                            for (ArtifactVersion av : availableVersions) {
                                d.addAvailableVersion(av.toString());
                            }
                        }
                        getLog().debug(String.format("Adding project reference %s on dependency %s",
                                project.getName(), d.getDisplayFileName()));
                    } else if (getLog().isDebugEnabled()) {
                        final String msg = String.format("More than 1 dependency was identified in first pass scan of '%s' in project %s",
                                dependencyNode.getArtifact().getId(), project.getName());
                        getLog().debug(msg);
                    }
                } else if ("import".equals(dependencyNode.getArtifact().getScope())) {
                    final String msg = String.format("Skipping '%s:%s' in project %s as it uses an `import` scope",
                            dependencyNode.getArtifact().getId(), dependencyNode.getArtifact().getScope(), project.getName());
                    getLog().debug(msg);
                } else if ("pom".equals(dependencyNode.getArtifact().getType())) {

                    try {
                        final Dependency d = new Dependency(artifactFile.getAbsoluteFile());
                        final Model pom = PomUtils.readPom(artifactFile.getAbsoluteFile());
                        JarAnalyzer.setPomEvidence(d, pom, null, true);
                        engine.addDependency(d);
                    } catch (AnalysisException ex) {
                        if (exCol == null) {
                            exCol = new ExceptionCollection();
                        }
                        exCol.addException(ex);
                        getLog().debug("Error reading pom " + artifactFile.getAbsoluteFile(), ex);
                    }
                } else {
                    if (!scannedFiles.contains(artifactFile)) {
                        final String msg = String.format("No analyzer could be found or the artifact has been scanned twice for '%s:%s' in project %s",
                                dependencyNode.getArtifact().getId(), dependencyNode.getArtifact().getScope(), project.getName());
                        getLog().warn(msg);
                    }
                }
            } else {
                final String msg = String.format("Unable to resolve '%s' in project %s",
                        dependencyNode.getArtifact().getId(), project.getName());
                getLog().debug(msg);
                if (exCol == null) {
                    exCol = new ExceptionCollection();
                }
            }
        }
        return exCol;
    }
    //CSON: OperatorWrap

    /**
     * Utility method for a work-around to MSHARED-998
     *
     * @param allDeps The Iterable of the resolved artifacts for all
     * dependencies
     * @param theCoord The ArtifactCoordinate of the artifact-with-classifier we
     * intended to resolve
     * @param project The project in whose context resolution was attempted
     * @return the resolved artifact matching with {@code theCoord}
     * @throws DependencyNotFoundException Not expected to be thrown, but will
     * be thrown if {@code theCoord} could not be found within {@code allDeps}
     */
    private Artifact findClassifierArtifactInAllDeps(final Iterable<ArtifactResult> allDeps, final ArtifactCoordinate theCoord,
                                                     final MavenProject project)
            throws DependencyNotFoundException {
        Artifact result = null;
        for (final ArtifactResult res : allDeps) {
            if (sameArtifact(res, theCoord)) {
                result = res.getArtifact();
                break;
            }
        }
        if (result == null) {
            throw new DependencyNotFoundException(String.format("Expected dependency not found in resolved artifacts for "
                    + "dependency %s of project-artifact %s", theCoord, project.getArtifactId()));
        }
        return result;
    }

    /**
     * Utility method for a work-around to MSHARED-998
     *
     * @param res A single ArtifactResult obtained from the DependencyResolver
     * @param theCoord The coordinates of the Artifact that we try to find
     * @return {@code true} when theCoord is non-null and matches with the
     * artifact of res
     */
    private boolean sameArtifact(final ArtifactResult res, final ArtifactCoordinate theCoord) {
        if (res == null || res.getArtifact() == null || theCoord == null) {
            return false;
        }
        boolean result = Objects.equals(res.getArtifact().getGroupId(), theCoord.getGroupId());
        result &= Objects.equals(res.getArtifact().getArtifactId(), theCoord.getArtifactId());
        result &= Objects.equals(res.getArtifact().getVersion(), theCoord.getVersion());
        result &= Objects.equals(res.getArtifact().getClassifier(), theCoord.getClassifier());
        result &= Objects.equals(res.getArtifact().getType(), theCoord.getExtension());
        return result;
    }

    /**
     * @param project the {@link MavenProject}
     * @param dependencyNode the {@link DependencyNode}
     * @return the name to be used when creating a
     * {@link Dependency#getProjectReferences() project reference} in a
     * {@link Dependency}. The behavior of this method returns {@link MavenProject#getName() project.getName()}<code> + ":" +
     * </code>
     * {@link DependencyNode#getArtifact() dependencyNode.getArtifact()}{@link Artifact#getScope() .getScope()}.
     */
    protected String createProjectReferenceName(MavenProject project, DependencyNode dependencyNode) {
        return project.getName() + ":" + dependencyNode.getArtifact().getScope();
    }

    /**
     * Scans the projects dependencies including the default (or defined)
     * FileSets.
     *
     * @param engine the core dependency-check engine
     * @param project the project being scanned
     * @param nodes the list of dependency nodes, generally obtained via the
     * DependencyGraphBuilder
     * @param buildingRequest the Maven project building request
     * @param aggregate whether the scan is part of an aggregate build
     * @return a collection of exceptions that may have occurred while resolving
     * and scanning the dependencies
     */
    private ExceptionCollection collectDependencies(Engine engine, MavenProject project,
            List<DependencyNode> nodes, ProjectBuildingRequest buildingRequest, boolean aggregate) {

        ExceptionCollection exCol;
        exCol = collectMavenDependencies(engine, project, nodes, buildingRequest, aggregate);

        final List<FileSet> projectScan;

        if (scanDirectory != null && !scanDirectory.isEmpty()) {
            if (scanSet == null) {
                scanSet = new ArrayList<>();
            }
            scanDirectory.stream().forEach(d -> {
                final FileSet fs = new FileSet();
                fs.setDirectory(d);
                fs.addInclude(INCLUDE_ALL);
                scanSet.add(fs);
            });
        }

        if (scanSet == null || scanSet.isEmpty()) {
            // Define the default FileSets
            final FileSet resourcesSet = new FileSet();
            final FileSet filtersSet = new FileSet();
            final FileSet webappSet = new FileSet();
            final FileSet mixedLangSet = new FileSet();
            try {
                resourcesSet.setDirectory(new File(project.getBasedir(), "src/main/resources").getCanonicalPath());
                resourcesSet.addInclude(INCLUDE_ALL);
                filtersSet.setDirectory(new File(project.getBasedir(), "src/main/filters").getCanonicalPath());
                filtersSet.addInclude(INCLUDE_ALL);
                webappSet.setDirectory(new File(project.getBasedir(), "src/main/webapp").getCanonicalPath());
                webappSet.addInclude(INCLUDE_ALL);
                mixedLangSet.setDirectory(project.getBasedir().getCanonicalPath());
                mixedLangSet.addInclude("package.json");
                mixedLangSet.addInclude("package-lock.json");
                mixedLangSet.addInclude("npm-shrinkwrap.json");
                mixedLangSet.addInclude("Gopkg.lock");
                mixedLangSet.addInclude("go.mod");
            } catch (IOException ex) {
                if (exCol == null) {
                    exCol = new ExceptionCollection();
                }
                exCol.addException(ex);
            }
            projectScan = new ArrayList<>();
            projectScan.add(resourcesSet);
            projectScan.add(filtersSet);
            projectScan.add(webappSet);
            projectScan.add(mixedLangSet);

        } else if (aggregate) {
            projectScan = new ArrayList<>();
            for (FileSet copyFrom : scanSet) {
                //deep copy of the FileSet - modifying the directory if it is not absolute.
                final FileSet fsCopy = new FileSet();
                final File f = new File(copyFrom.getDirectory());
                if (f.isAbsolute()) {
                    fsCopy.setDirectory(copyFrom.getDirectory());
                } else {
                    try {
                        fsCopy.setDirectory(new File(project.getBasedir(), copyFrom.getDirectory()).getCanonicalPath());
                    } catch (IOException ex) {
                        if (exCol == null) {
                            exCol = new ExceptionCollection();
                        }
                        exCol.addException(ex);
                        fsCopy.setDirectory(copyFrom.getDirectory());
                    }
                }
                fsCopy.setDirectoryMode(copyFrom.getDirectoryMode());
                fsCopy.setExcludes(copyFrom.getExcludes());
                fsCopy.setFileMode(copyFrom.getFileMode());
                fsCopy.setFollowSymlinks(copyFrom.isFollowSymlinks());
                fsCopy.setIncludes(copyFrom.getIncludes());
                fsCopy.setLineEnding(copyFrom.getLineEnding());
                fsCopy.setMapper(copyFrom.getMapper());
                fsCopy.setModelEncoding(copyFrom.getModelEncoding());
                fsCopy.setOutputDirectory(copyFrom.getOutputDirectory());
                fsCopy.setUseDefaultExcludes(copyFrom.isUseDefaultExcludes());
                projectScan.add(fsCopy);
            }
        } else {
            projectScan = scanSet;
        }

        // Iterate through FileSets and scan included files
        final FileSetManager fileSetManager = new FileSetManager();
        for (FileSet fileSet : projectScan) {
            getLog().debug("Scanning fileSet: " + fileSet.getDirectory());
            final String[] includedFiles = fileSetManager.getIncludedFiles(fileSet);
            for (String include : includedFiles) {
                final File includeFile = new File(fileSet.getDirectory(), include).getAbsoluteFile();
                if (includeFile.exists()) {
                    engine.scan(includeFile, project.getName());
                }
            }
        }
        return exCol;
    }

    /**
     * Checks if the current artifact is actually in the reactor projects that
     * have not yet been built. If true a virtual dependency is created based on
     * the evidence in the project.
     *
     * @param engine a reference to the engine being used to scan
     * @param artifact the artifact being analyzed in the mojo
     * @return <code>true</code> if the artifact is in the reactor; otherwise
     * <code>false</code>
     */
    private boolean addReactorDependency(Engine engine, Artifact artifact) {
        return addVirtualDependencyFromReactor(engine, artifact, "Unable to resolve %s as it has not been built yet "
                + "- creating a virtual dependency instead.");
    }

    /**
     * Checks if the current artifact is actually in the reactor projects. If
     * true a virtual dependency is created based on the evidence in the
     * project.
     *
     * @param engine a reference to the engine being used to scan
     * @param artifact the artifact being analyzed in the mojo
     * @param infoLogTemplate the template for the infoLog entry written when a
     * virtual dependency is added. Needs a single %s placeholder for the
     * location of the displayName in the message
     * @return <code>true</code> if the artifact is in the reactor; otherwise
     * <code>false</code>
     */
    private boolean addVirtualDependencyFromReactor(Engine engine, Artifact artifact, String infoLogTemplate) {

        getLog().debug(String.format("Checking the reactor projects (%d) for %s:%s:%s",
                reactorProjects.size(),
                artifact.getGroupId(), artifact.getArtifactId(), artifact.getVersion()));

        for (MavenProject prj : reactorProjects) {

            getLog().debug(String.format("Comparing %s:%s:%s to %s:%s:%s",
                    artifact.getGroupId(), artifact.getArtifactId(), artifact.getBaseVersion(),
                    prj.getGroupId(), prj.getArtifactId(), prj.getVersion()));

            if (prj.getArtifactId().equals(artifact.getArtifactId())
                    && prj.getGroupId().equals(artifact.getGroupId())
                    && prj.getVersion().equals(artifact.getBaseVersion())) {

                final String displayName = String.format("%s:%s:%s",
                        prj.getGroupId(), prj.getArtifactId(), prj.getVersion());
                getLog().info(String.format(infoLogTemplate,
                        displayName));
                final Dependency d = newDependency(prj);
                final String key = String.format("%s:%s:%s", prj.getGroupId(), prj.getArtifactId(), prj.getVersion());
                d.setSha1sum(Checksum.getSHA1Checksum(key));
                d.setSha256sum(Checksum.getSHA256Checksum(key));
                d.setMd5sum(Checksum.getMD5Checksum(key));
                d.setEcosystem(JarAnalyzer.DEPENDENCY_ECOSYSTEM);
                d.setDisplayFileName(displayName);

                d.addEvidence(EvidenceType.PRODUCT, "project", "artifactid", prj.getArtifactId(), Confidence.HIGHEST);
                d.addEvidence(EvidenceType.VENDOR, "project", "artifactid", prj.getArtifactId(), Confidence.LOW);

                d.addEvidence(EvidenceType.VENDOR, "project", "groupid", prj.getGroupId(), Confidence.HIGHEST);
                d.addEvidence(EvidenceType.PRODUCT, "project", "groupid", prj.getGroupId(), Confidence.LOW);
                d.setEcosystem(JarAnalyzer.DEPENDENCY_ECOSYSTEM);
                Identifier id;
                try {
                    id = new PurlIdentifier(StandardTypes.MAVEN, artifact.getGroupId(),
                            artifact.getArtifactId(), artifact.getVersion(), Confidence.HIGHEST);
                } catch (MalformedPackageURLException ex) {
                    getLog().debug("Unable to create PackageURL object:" + key);
                    id = new GenericIdentifier("maven:" + key, Confidence.HIGHEST);
                }
                d.addSoftwareIdentifier(id);
                //TODO unify the setName/version and package path - they are equivelent ideas submitted by two seperate committers
                d.setName(String.format("%s:%s", prj.getGroupId(), prj.getArtifactId()));
                d.setVersion(prj.getVersion());
                d.setPackagePath(displayName);
                if (prj.getDescription() != null) {
                    JarAnalyzer.addDescription(d, prj.getDescription(), "project", "description");
                }
                for (License l : prj.getLicenses()) {
                    final StringBuilder license = new StringBuilder();
                    if (l.getName() != null) {
                        license.append(l.getName());
                    }
                    if (l.getUrl() != null) {
                        license.append(" ").append(l.getUrl());
                    }
                    if (d.getLicense() == null) {
                        d.setLicense(license.toString());
                    } else if (!d.getLicense().contains(license)) {
                        d.setLicense(String.format("%s%n%s", d.getLicense(), license.toString()));
                    }
                }
                engine.addDependency(d);
                return true;
            }
        }
        return false;
    }

    Dependency newDependency(MavenProject prj) {
        final File pom = new File(prj.getBasedir(), "pom.xml");

        if (pom.isFile()) {
            getLog().debug("Adding virtual dependency from pom.xml");
            return new Dependency(pom, true);
        } else if (prj.getFile().isFile()) {
            getLog().debug("Adding virtual dependency from file");
            return new Dependency(prj.getFile(), true);
        } else {
            return new Dependency(true);
        }
    }

    /**
     * Checks if the current artifact is actually in the reactor projects. If
     * true a virtual dependency is created based on the evidence in the
     * project.
     *
     * @param engine a reference to the engine being used to scan
     * @param artifact the artifact being analyzed in the mojo
     * @return <code>true</code> if the artifact is a snapshot artifact in the
     * reactor; otherwise <code>false</code>
     */
    private boolean addSnapshotReactorDependency(Engine engine, Artifact artifact) {
        if (!artifact.isSnapshot()) {
            return false;
        }
        return addVirtualDependencyFromReactor(engine, artifact, "Found snapshot reactor project in aggregate for %s - "
                + "creating a virtual dependency as the snapshot found in the repository may contain outdated dependencies.");
    }

    /**
     * @param project The target project to create a building request for.
     * @return Returns a new ProjectBuildingRequest populated from the current
     * session and the target project remote repositories, used to resolve
     * artifacts.
     */
    public ProjectBuildingRequest newResolveArtifactProjectBuildingRequest(MavenProject project) {
        final ProjectBuildingRequest buildingRequest = new DefaultProjectBuildingRequest(session.getProjectBuildingRequest());
        buildingRequest.setRemoteRepositories(new ArrayList<>(project.getRemoteArtifactRepositories()));
        buildingRequest.setProject(project);
        return buildingRequest;
    }

    /**
     * Executes the dependency-check scan and generates the necessary report.
     *
     * @throws MojoExecutionException thrown if there is an exception running
     * the scan
     * @throws MojoFailureException thrown if dependency-check is configured to
     * fail the build
     */
    protected void runCheck() throws MojoExecutionException, MojoFailureException {
        muteJCS();
        try (Engine engine = initializeEngine()) {
            ExceptionCollection exCol = scanDependencies(engine);
            try {
                engine.analyzeDependencies();
            } catch (ExceptionCollection ex) {
                exCol = handleAnalysisExceptions(exCol, ex);
            }
            if (exCol == null || !exCol.isFatal()) {

                File outputDir = getCorrectOutputDirectory(this.getProject());
                if (outputDir == null) {
                    //in some regards we shouldn't be writing this, but we are anyway.
                    //we shouldn't write this because nothing is configured to generate this report.
                    outputDir = new File(this.getProject().getBuild().getDirectory());
                }
                try {
                    final MavenProject p = this.getProject();
                    for (String f : getFormats()) {
                        engine.writeReports(p.getName(), p.getGroupId(), p.getArtifactId(), p.getVersion(), outputDir, f, exCol);
                    }
                } catch (ReportException ex) {
                    if (exCol == null) {
                        exCol = new ExceptionCollection(ex);
                    } else {
                        exCol.addException(ex);
                    }
                    if (this.isFailOnError()) {
                        throw new MojoExecutionException("One or more exceptions occurred during dependency-check analysis", exCol);
                    } else {
                        getLog().debug("Error writing the report", ex);
                    }
                }
                showSummary(this.getProject(), engine.getDependencies());
                checkForFailure(engine.getDependencies());
                if (exCol != null && this.isFailOnError()) {
                    throw new MojoExecutionException("One or more exceptions occurred during dependency-check analysis", exCol);
                }
            }
        } catch (DatabaseException ex) {
            if (getLog().isDebugEnabled()) {
                getLog().debug("Database connection error", ex);
            }
            final String msg = "An exception occurred connecting to the local database. Please see the log file for more details.";
            if (this.isFailOnError()) {
                throw new MojoExecutionException(msg, ex);
            }
            getLog().error(msg, ex);
        } finally {
            getSettings().cleanup();
        }
    }

    /**
     * Combines the two exception collections and if either are fatal, throw an
     * MojoExecutionException
     *
     * @param currentEx the primary exception collection
     * @param newEx the new exception collection to add
     * @return the combined exception collection
     * @throws MojoExecutionException thrown if dependency-check is configured
     * to fail on errors
     */
    private ExceptionCollection handleAnalysisExceptions(ExceptionCollection currentEx, ExceptionCollection newEx) throws MojoExecutionException {
        ExceptionCollection returnEx = currentEx;
        if (returnEx == null) {
            returnEx = newEx;
        } else {
            returnEx.getExceptions().addAll(newEx.getExceptions());
            if (newEx.isFatal()) {
                returnEx.setFatal(true);
            }
        }
        if (returnEx.isFatal()) {
            final String msg = String.format("Fatal exception(s) analyzing %s", getProject().getName());
            if (this.isFailOnError()) {
                throw new MojoExecutionException(msg, returnEx);
            }
            getLog().error(msg);
            if (getLog().isDebugEnabled()) {
                getLog().debug(returnEx);
            }
        } else {
            final String msg = String.format("Exception(s) analyzing %s", getProject().getName());
            if (getLog().isDebugEnabled()) {
                getLog().debug(msg, returnEx);
            }
        }
        return returnEx;
    }

    /**
     * Scans the dependencies of the projects in aggregate.
     *
     * @param engine the engine used to perform the scanning
     * @return a collection of exceptions
     * @throws MojoExecutionException thrown if a fatal exception occurs
     */
    protected abstract ExceptionCollection scanDependencies(Engine engine) throws MojoExecutionException;

    /**
     * Returns the report output directory.
     *
     * @return the report output directory
     */
    @Override
    public File getReportOutputDirectory() {
        return reportOutputDirectory;
    }

    /**
     * Sets the Reporting output directory.
     *
     * @param directory the output directory
     */
    @Override
    public void setReportOutputDirectory(File directory) {
        reportOutputDirectory = directory;
    }

    /**
     * Returns the output directory.
     *
     * @return the output directory
     */
    public File getOutputDirectory() {
        return outputDirectory;
    }

    /**
     * Returns whether this is an external report. This method always returns
     * true.
     *
     * @return <code>true</code>
     */
    @Override
    public final boolean isExternalReport() {
        return true;
    }

    /**
     * Returns the output name.
     *
     * @return the output name
     */
    @Override
    public String getOutputName() {
        final Set<String> selectedFormats = getFormats();
        if (selectedFormats.contains("HTML") || selectedFormats.contains("ALL") || selectedFormats.size() > 1) {
            return "dependency-check-report";
        } else if (selectedFormats.contains("XML")) {
            return "dependency-check-report.xml";
        } else if (selectedFormats.contains("JUNIT")) {
            return "dependency-check-junit.xml";
        } else if (selectedFormats.contains("JSON")) {
            return "dependency-check-report.json";
        } else if (selectedFormats.contains("CSV")) {
            return "dependency-check-report.csv";
        } else {
            getLog().warn("Unknown report format used during site generation.");
            return "dependency-check-report";
        }
    }

    /**
     * Returns the category name.
     *
     * @return the category name
     */
    @Override
    public String getCategoryName() {
        return MavenReport.CATEGORY_PROJECT_REPORTS;
    }
    //</editor-fold>

    /**
     * Initializes a new <code>Engine</code> that can be used for scanning. This
     * method should only be called in a try-with-resources to ensure that the
     * engine is properly closed.
     *
     * @return a newly instantiated <code>Engine</code>
     * @throws DatabaseException thrown if there is a database exception
     */
    protected Engine initializeEngine() throws DatabaseException {
        populateSettings();
        return new Engine(settings);
    }

    /**
     * Takes the properties supplied and updates the dependency-check settings.
     * Additionally, this sets the system properties required to change the
     * proxy URL, port, and connection timeout.
     */
    protected void populateSettings() {
        settings = new Settings();
        InputStream mojoProperties = null;
        try {
            mojoProperties = this.getClass().getClassLoader().getResourceAsStream(PROPERTIES_FILE);
            settings.mergeProperties(mojoProperties);
        } catch (IOException ex) {
            getLog().warn("Unable to load the dependency-check maven mojo.properties file.");
            if (getLog().isDebugEnabled()) {
                getLog().debug("", ex);
            }
        } finally {
            if (mojoProperties != null) {
                try {
                    mojoProperties.close();
                } catch (IOException ex) {
                    if (getLog().isDebugEnabled()) {
                        getLog().debug("", ex);
                    }
                }
            }
        }
        settings.setStringIfNotEmpty(Settings.KEYS.MAVEN_LOCAL_REPO, mavenSettings.getLocalRepository());
        settings.setBooleanIfNotNull(Settings.KEYS.AUTO_UPDATE, autoUpdate);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_EXPERIMENTAL_ENABLED, enableExperimental);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_RETIRED_ENABLED, enableRetired);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_GOLANG_DEP_ENABLED, golangDepEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_GOLANG_MOD_ENABLED, golangModEnabled);
        settings.setStringIfNotNull(Settings.KEYS.ANALYZER_GOLANG_PATH, pathToGo);
        settings.setStringIfNotNull(Settings.KEYS.ANALYZER_YARN_PATH, pathToYarn);
        settings.setStringIfNotNull(Settings.KEYS.ANALYZER_PNPM_PATH, pathToPnpm);

        final Proxy proxy = getMavenProxy();
        if (proxy != null) {
            settings.setString(Settings.KEYS.PROXY_SERVER, proxy.getHost());
            settings.setString(Settings.KEYS.PROXY_PORT, Integer.toString(proxy.getPort()));
            final String userName = proxy.getUsername();
            String password = proxy.getPassword();
            if (password != null && !password.isEmpty()) {
                if (settings.getBoolean(Settings.KEYS.PROXY_DISABLE_SCHEMAS, true)) {
                    System.setProperty("jdk.http.auth.tunneling.disabledSchemes", "");
                }
                try {
                    password = decryptPasswordFromSettings(password);
                } catch (SecDispatcherException ex) {
                    password = handleSecDispatcherException("proxy", proxy.getId(), password, ex);
                }
            }
            settings.setStringIfNotNull(Settings.KEYS.PROXY_USERNAME, userName);
            settings.setStringIfNotNull(Settings.KEYS.PROXY_PASSWORD, password);
            settings.setStringIfNotNull(Settings.KEYS.PROXY_NON_PROXY_HOSTS, proxy.getNonProxyHosts());
        }
        final String[] suppressions = determineSuppressions();
        settings.setArrayIfNotEmpty(Settings.KEYS.SUPPRESSION_FILE, suppressions);
        settings.setBooleanIfNotNull(Settings.KEYS.UPDATE_VERSION_CHECK_ENABLED, versionCheckEnabled);
        settings.setStringIfNotEmpty(Settings.KEYS.CONNECTION_TIMEOUT, connectionTimeout);
        settings.setStringIfNotEmpty(Settings.KEYS.HINTS_FILE, hintsFile);
        settings.setFloat(Settings.KEYS.JUNIT_FAIL_ON_CVSS, junitFailOnCVSS);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_JAR_ENABLED, jarAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_NUSPEC_ENABLED, nuspecAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_NUGETCONF_ENABLED, nugetconfAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_CENTRAL_ENABLED, centralAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_CENTRAL_USE_CACHE, centralAnalyzerUseCache);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_ARTIFACTORY_ENABLED, artifactoryAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_NEXUS_ENABLED, nexusAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_ASSEMBLY_ENABLED, assemblyAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_MSBUILD_PROJECT_ENABLED, msbuildAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_ARCHIVE_ENABLED, archiveAnalyzerEnabled);
        settings.setStringIfNotEmpty(Settings.KEYS.ADDITIONAL_ZIP_EXTENSIONS, zipExtensions);
        settings.setStringIfNotEmpty(Settings.KEYS.ANALYZER_ASSEMBLY_DOTNET_PATH, pathToCore);
        settings.setStringIfNotEmpty(Settings.KEYS.ANALYZER_NEXUS_URL, nexusUrl);
        configureServerCredentials(nexusServerId, Settings.KEYS.ANALYZER_NEXUS_USER, Settings.KEYS.ANALYZER_NEXUS_PASSWORD);

        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_NEXUS_USES_PROXY, nexusUsesProxy);
        settings.setStringIfNotNull(Settings.KEYS.ANALYZER_ARTIFACTORY_URL, artifactoryAnalyzerUrl);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_ARTIFACTORY_USES_PROXY, artifactoryAnalyzerUseProxy);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_ARTIFACTORY_PARALLEL_ANALYSIS, artifactoryAnalyzerParallelAnalysis);
        if (Boolean.TRUE.equals(artifactoryAnalyzerEnabled)) {
            if (artifactoryAnalyzerServerId != null) {
                configureServerCredentials(artifactoryAnalyzerServerId, Settings.KEYS.ANALYZER_ARTIFACTORY_API_USERNAME,
                        Settings.KEYS.ANALYZER_ARTIFACTORY_API_TOKEN);
            } else {
                settings.setStringIfNotNull(Settings.KEYS.ANALYZER_ARTIFACTORY_API_USERNAME, artifactoryAnalyzerUsername);
                settings.setStringIfNotNull(Settings.KEYS.ANALYZER_ARTIFACTORY_API_TOKEN, artifactoryAnalyzerApiToken);
            }
            settings.setStringIfNotNull(Settings.KEYS.ANALYZER_ARTIFACTORY_BEARER_TOKEN, artifactoryAnalyzerBearerToken);
        }
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_PYTHON_DISTRIBUTION_ENABLED, pyDistributionAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_PYTHON_PACKAGE_ENABLED, pyPackageAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_RUBY_GEMSPEC_ENABLED, rubygemsAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_OPENSSL_ENABLED, opensslAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_CMAKE_ENABLED, cmakeAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_AUTOCONF_ENABLED, autoconfAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_PIP_ENABLED, pipAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_PIPFILE_ENABLED, pipfileAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_COMPOSER_LOCK_ENABLED, composerAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_CPANFILE_ENABLED, cpanfileAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_NODE_PACKAGE_ENABLED, nodeAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_NODE_AUDIT_ENABLED, nodeAuditAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_NODE_AUDIT_USE_CACHE, nodeAuditAnalyzerUseCache);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_NODE_PACKAGE_SKIPDEV, nodePackageSkipDevDependencies);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_NODE_AUDIT_SKIPDEV, nodeAuditSkipDevDependencies);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_YARN_AUDIT_ENABLED, yarnAuditAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_PNPM_AUDIT_ENABLED, pnpmAuditAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_RETIREJS_ENABLED, retireJsAnalyzerEnabled);
        settings.setStringIfNotNull(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_URL, retireJsUrl);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_RETIREJS_FORCEUPDATE, retireJsForceUpdate);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_MIX_AUDIT_ENABLED, mixAuditAnalyzerEnabled);
        settings.setStringIfNotNull(Settings.KEYS.ANALYZER_MIX_AUDIT_PATH, mixAuditPath);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_BUNDLE_AUDIT_ENABLED, bundleAuditAnalyzerEnabled);
        settings.setStringIfNotNull(Settings.KEYS.ANALYZER_BUNDLE_AUDIT_PATH, bundleAuditPath);
        settings.setStringIfNotNull(Settings.KEYS.ANALYZER_BUNDLE_AUDIT_WORKING_DIRECTORY, bundleAuditWorkingDirectory);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_COCOAPODS_ENABLED, cocoapodsAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_SWIFT_PACKAGE_MANAGER_ENABLED, swiftPackageManagerAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_SWIFT_PACKAGE_RESOLVED_ENABLED, swiftPackageResolvedAnalyzerEnabled);

        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_OSSINDEX_ENABLED, ossindexAnalyzerEnabled);
        settings.setStringIfNotEmpty(Settings.KEYS.ANALYZER_OSSINDEX_URL, ossindexAnalyzerUrl);
        configureServerCredentials(ossIndexServerId, Settings.KEYS.ANALYZER_OSSINDEX_USER, Settings.KEYS.ANALYZER_OSSINDEX_PASSWORD);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_OSSINDEX_USE_CACHE, ossindexAnalyzerUseCache);

        if (retirejs != null) {
            settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_RETIREJS_FILTER_NON_VULNERABLE, retirejs.getFilterNonVulnerable());
            settings.setArrayIfNotEmpty(Settings.KEYS.ANALYZER_RETIREJS_FILTERS, retirejs.getFilters());
        }

        //Database configuration
        settings.setStringIfNotEmpty(Settings.KEYS.DB_DRIVER_NAME, databaseDriverName);
        settings.setStringIfNotEmpty(Settings.KEYS.DB_DRIVER_PATH, databaseDriverPath);
        settings.setStringIfNotEmpty(Settings.KEYS.DB_CONNECTION_STRING, connectionString);

        if (databaseUser == null && databasePassword == null && serverId != null) {
            configureServerCredentials(serverId, Settings.KEYS.DB_USER, Settings.KEYS.DB_PASSWORD);
        } else {
            settings.setStringIfNotEmpty(Settings.KEYS.DB_USER, databaseUser);
            settings.setStringIfNotEmpty(Settings.KEYS.DB_PASSWORD, databasePassword);
        }
        settings.setStringIfNotEmpty(Settings.KEYS.DATA_DIRECTORY, dataDirectory);
        settings.setStringIfNotEmpty(Settings.KEYS.DB_FILE_NAME, dbFilename);

        final String cveModifiedJson = Optional.ofNullable(cveUrlModified)
                .filter(arg -> !arg.isEmpty())
                .orElseGet(this::getDefaultCveUrlModified);
        settings.setStringIfNotEmpty(Settings.KEYS.CVE_MODIFIED_JSON, cveModifiedJson);
        settings.setStringIfNotEmpty(Settings.KEYS.CVE_BASE_JSON, cveUrlBase);
        settings.setStringIfNotEmpty(Settings.KEYS.CVE_DOWNLOAD_WAIT_TIME, cveWaitTime);
        settings.setIntIfNotNull(Settings.KEYS.CVE_CHECK_VALID_FOR_HOURS, cveValidForHours);
        if (cveStartYear != null && cveStartYear < 2002) {
            getLog().warn("Invalid configuration: cveStartYear must be 2002 or greater");
            cveStartYear = 2002;
        }
        settings.setIntIfNotNull(Settings.KEYS.CVE_START_YEAR, cveStartYear);
        settings.setBooleanIfNotNull(Settings.KEYS.PRETTY_PRINT, prettyPrint);
        artifactScopeExcluded = new ArtifactScopeExcluded(skipTestScope, skipProvidedScope, skipSystemScope, skipRuntimeScope);
        artifactTypeExcluded = new ArtifactTypeExcluded(skipArtifactType);
        if (cveUser == null && cvePassword == null && cveServerId != null) {
            configureServerCredentials(cveServerId, Settings.KEYS.CVE_USER, Settings.KEYS.CVE_PASSWORD);
        } else {
            settings.setStringIfNotEmpty(Settings.KEYS.CVE_USER, cveUser);
            settings.setStringIfNotEmpty(Settings.KEYS.CVE_PASSWORD, cvePassword);
        }
        if (suppressionFileUser == null && suppressionFilePassword == null && suppressionFileServerId != null) {
            configureServerCredentials(suppressionFileServerId, Settings.KEYS.SUPPRESSION_FILE_USER, Settings.KEYS.SUPPRESSION_FILE_PASSWORD);
        } else {
            settings.setStringIfNotEmpty(Settings.KEYS.SUPPRESSION_FILE_USER, suppressionFileUser);
            settings.setStringIfNotEmpty(Settings.KEYS.SUPPRESSION_FILE_PASSWORD, suppressionFilePassword);
        }
    }

    /**
     * Retrieves the server credentials from the settings.xml, decrypts the
     * password, and places the values into the settings under the given key
     * names.
     *
     * @param serverId the server id
     * @param userSettingKey the property name for the username
     * @param passwordSettingKey the property name for the password
     */
    private void configureServerCredentials(String serverId, String userSettingKey, String passwordSettingKey) {
        if (serverId != null) {
            final Server server = settingsXml.getServer(serverId);
            if (server != null) {
                final String username = server.getUsername();
                String password = null;
                try {
                    password = decryptPasswordFromSettings(server.getPassword());
                } catch (SecDispatcherException ex) {
                    password = handleSecDispatcherException("server", serverId, server.getPassword(), ex);
                }
                settings.setStringIfNotEmpty(userSettingKey, username);
                settings.setStringIfNotEmpty(passwordSettingKey, password);
            } else {
                getLog().error(String.format("Server '%s' not found in the settings.xml file", serverId));
            }
        }
    }

    /**
     * Decrypts a password from the Maven settings if it needs to be decrypted.
     * If it's not encrypted the input password will be returned unchanged.
     *
     * @param password the original password value from the settings.xml
     * @return the decrypted password from the Maven configuration
     * @throws SecDispatcherException thrown if there is an error decrypting the
     * password
     */
    private String decryptPasswordFromSettings(String password) throws SecDispatcherException {
        //The following fix was copied from:
        //   https://github.com/bsorrentino/maven-confluence-plugin/blob/master/maven-confluence-reporting-plugin/src/main/java/org/bsc/maven/confluence/plugin/AbstractBaseConfluenceMojo.java
        //
        // FIX to resolve
        // org.sonatype.plexus.components.sec.dispatcher.SecDispatcherException:
        // java.io.FileNotFoundException: ~/.settings-security.xml (No such file or directory)
        //
        if (securityDispatcher instanceof DefaultSecDispatcher) {
            ((DefaultSecDispatcher) securityDispatcher).setConfigurationFile("~/.m2/settings-security.xml");
        }

        return securityDispatcher.decrypt(password);
    }

    /**
     * Handles a SecDispatcherException that was thrown at an attempt to decrypt
     * an encrypted password from the Maven settings.
     *
     * @param settingsElementName - "server" or "proxy"
     * @param settingsElementId - value of the id attribute of the proxy resp.
     * server element to which the password belongs
     * @param passwordValueFromSettings - original, undecrypted password value
     * from the settings
     * @param ex - the Exception to handle
     * @return the password fallback value to go on with, might be a not working
     * one.
     */
    private String handleSecDispatcherException(String settingsElementName, String settingsElementId, String passwordValueFromSettings,
            SecDispatcherException ex) {
        String password = passwordValueFromSettings;
        if (ex.getCause() instanceof FileNotFoundException
                || (ex.getCause() != null && ex.getCause().getCause() instanceof FileNotFoundException)) {
            //maybe its not encrypted?
            final String tmp = passwordValueFromSettings;
            if (tmp.startsWith("{") && tmp.endsWith("}")) {
                getLog().error(String.format(
                        "Unable to decrypt the %s password for %s id '%s' in settings.xml%n\tCause: %s",
                        settingsElementName, settingsElementName, settingsElementId, ex.getMessage()));
            } else {
                password = tmp;
            }
        } else {
            getLog().error(String.format(
                    "Unable to decrypt the %s password for %s id '%s' in settings.xml%n\tCause: %s",
                    settingsElementName, settingsElementName, settingsElementId, ex.getMessage()));
        }
        return password;
    }

    /**
     * Combines the configured suppressionFile and suppressionFiles into a
     * single array.
     *
     * @return an array of suppression file paths
     */
    private String[] determineSuppressions() {
        String[] suppressions = suppressionFiles;
        if (suppressionFile != null) {
            if (suppressions == null) {
                suppressions = new String[]{suppressionFile};
            } else {
                suppressions = Arrays.copyOf(suppressions, suppressions.length + 1);
                suppressions[suppressions.length - 1] = suppressionFile;
            }
        }
        return suppressions;
    }

    /**
     * Hacky method of muting the noisy logging from JCS. Implemented using a
     * solution from SO: https://stackoverflow.com/a/50723801
     */
    private void muteJCS() {
        final String[] noisyLoggers = {
            "org.apache.commons.jcs.auxiliary.disk.AbstractDiskCache",
            "org.apache.commons.jcs.engine.memory.AbstractMemoryCache",
            "org.apache.commons.jcs.engine.control.CompositeCache",
            "org.apache.commons.jcs.auxiliary.disk.indexed.IndexedDiskCache",
            "org.apache.commons.jcs.engine.control.CompositeCache",
            "org.apache.commons.jcs.engine.memory.AbstractMemoryCache",
            "org.apache.commons.jcs.engine.control.event.ElementEventQueue",
            "org.apache.commons.jcs.engine.memory.AbstractDoubleLinkedListMemoryCache",
            "org.apache.commons.jcs.auxiliary.AuxiliaryCacheConfigurator",
            "org.apache.commons.jcs.engine.control.CompositeCacheManager",
            "org.apache.commons.jcs.utils.threadpool.ThreadPoolManager",
            "org.apache.commons.jcs.engine.control.CompositeCacheConfigurator"};
        for (String loggerName : noisyLoggers) {
            try {
                //This is actually a MavenSimpleLogger, but due to various classloader issues, can't work with the directly.
                final Logger l = LoggerFactory.getLogger(loggerName);
                final Field f = l.getClass().getSuperclass().getDeclaredField("currentLogLevel");
                f.setAccessible(true);
                f.set(l, LocationAwareLogger.ERROR_INT);
            } catch (IllegalAccessException | IllegalArgumentException | NoSuchFieldException | SecurityException e) {
                getLog().debug("Failed to reset the log level of " + loggerName + ", it will continue being noisy.");
            }
        }
    }

    /**
     * Returns the maven proxy.
     *
     * @return the maven proxy
     */
    private Proxy getMavenProxy() {
        if (mavenSettings != null) {
            final List<Proxy> proxies = mavenSettings.getProxies();
            if (proxies != null && !proxies.isEmpty()) {
                if (mavenSettingsProxyId != null) {
                    for (Proxy proxy : proxies) {
                        if (mavenSettingsProxyId.equalsIgnoreCase(proxy.getId())) {
                            return proxy;
                        }
                    }
                } else {
                    for (Proxy aProxy : proxies) {
                        if (aProxy.isActive()) {
                            return aProxy;
                        }
                    }
                }
            }
        }
        return null;
    }

    /**
     * Returns a reference to the current project. This method is used instead
     * of auto-binding the project via component annotation in concrete
     * implementations of this. If the child has a
     * <code>@Component MavenProject project;</code> defined then the abstract
     * class (i.e. this class) will not have access to the current project (just
     * the way Maven works with the binding).
     *
     * @return returns a reference to the current project
     */
    protected MavenProject getProject() {
        return project;
    }

    /**
     * Returns the list of Maven Projects in this build.
     *
     * @return the list of Maven Projects in this build
     */
    protected List<MavenProject> getReactorProjects() {
        return reactorProjects;
    }

    /**
     * Combines the format and formats properties into a single collection.
     *
     * @return the selected report formats
     */
    private Set<String> getFormats() {
        final Set<String> invalid = new HashSet<>();
        final Set<String> selectedFormats = formats == null || formats.length == 0 ? new HashSet<>() : new HashSet<>(Arrays.asList(formats));
        selectedFormats.forEach((s) -> {
            try {
                ReportGenerator.Format.valueOf(s.toUpperCase());
            } catch (IllegalArgumentException ex) {
                invalid.add(s);
            }
        });
        invalid.forEach((s) -> {
            getLog().warn("Invalid report format specified: " + s);
        });
        if (selectedFormats.contains("true")) {
            selectedFormats.remove("true");
        }
        if (format != null && selectedFormats.isEmpty()) {
            selectedFormats.add(format);
        }
        return selectedFormats;
    }

    /**
     * Returns the list of excluded artifacts based on either artifact id or
     * group id and artifact id.
     *
     * @return a list of artifact to exclude
     */
    public List<String> getExcludes() {
        if (excludes == null) {
            excludes = new ArrayList<>();
        }
        return excludes;
    }

    /**
     * Returns the artifact scope excluded filter.
     *
     * @return the artifact scope excluded filter
     */
    protected Filter<String> getArtifactScopeExcluded() {
        return artifactScopeExcluded;
    }

    /**
     * Returns the configured settings.
     *
     * @return the configured settings
     */
    protected Settings getSettings() {
        return settings;
    }

    //<editor-fold defaultstate="collapsed" desc="Methods to fail build or show summary">
    /**
     * Checks to see if a vulnerability has been identified with a CVSS score
     * that is above the threshold set in the configuration.
     *
     * @param dependencies the list of dependency objects
     * @throws MojoFailureException thrown if a CVSS score is found that is
     * higher then the threshold set
     */
    protected void checkForFailure(Dependency[] dependencies) throws MojoFailureException {
        final StringBuilder ids = new StringBuilder();
        for (Dependency d : dependencies) {
            boolean addName = true;
            for (Vulnerability v : d.getVulnerabilities()) {
                if (failBuildOnAnyVulnerability || (v.getCvssV2() != null && v.getCvssV2().getScore() >= failBuildOnCVSS)
                        || (v.getCvssV3() != null && v.getCvssV3().getBaseScore() >= failBuildOnCVSS)
                        || (v.getUnscoredSeverity() != null && SeverityUtil.estimateCvssV2(v.getUnscoredSeverity()) >= failBuildOnCVSS)
                        //safety net to fail on any if for some reason the above misses on 0
                        || (failBuildOnCVSS <= 0.0f)) {
                    if (addName) {
                        addName = false;
                        ids.append(NEW_LINE).append(d.getFileName()).append(": ");
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
                if (failBuildOnAnyVulnerability) {
                    msg = String.format("%n%nOne or more dependencies were identified with vulnerabilities: %n%s%n%n"
                            + "See the dependency-check report for more details.%n%n", ids.toString());
                } else {
                    msg = String.format("%n%nOne or more dependencies were identified with vulnerabilities that have a CVSS score greater than or "
                            + "equal to '%.1f': %n%s%n%nSee the dependency-check report for more details.%n%n", failBuildOnCVSS, ids.toString());
                }
            } else {
                msg = String.format("%n%nOne or more dependencies were identified with vulnerabilities.%n%n"
                        + "See the dependency-check report for more details.%n%n");
            }
            throw new MojoFailureException(msg);
        }
    }

    /**
     * Generates a warning message listing a summary of dependencies and their
     * associated CPE and CVE entries.
     *
     * @param mp the Maven project for which the summary is shown
     * @param dependencies a list of dependency objects
     */
    protected void showSummary(MavenProject mp, Dependency[] dependencies) {
        if (showSummary) {
            DependencyCheckScanAgent.showSummary(mp.getName(), dependencies);
        }
    }

    private String getDefaultCveUrlModified() {
        return CveUrlParser.newInstance(getSettings())
                .getDefaultCveUrlModified(cveUrlBase);
    }

    //</editor-fold>
}
//CSON: FileLength
