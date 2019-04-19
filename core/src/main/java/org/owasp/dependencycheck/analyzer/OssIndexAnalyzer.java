package org.owasp.dependencycheck.analyzer;

import org.sonatype.ossindex.service.api.componentreport.ComponentReport;
import org.sonatype.ossindex.service.api.componentreport.ComponentReportVulnerability;
import org.sonatype.ossindex.service.api.cvss.Cvss2Severity;
import org.sonatype.ossindex.service.api.cvss.Cvss2Vector;
import org.sonatype.ossindex.service.api.cvss.Cvss3Severity;
import org.sonatype.ossindex.service.api.cvss.Cvss3Vector;
import org.sonatype.ossindex.service.api.cvss.CvssVector;
import org.sonatype.ossindex.service.api.cvss.CvssVectorFactory;
import org.sonatype.ossindex.service.client.OssindexClient;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.ossindex.OssindexClientFactory;
import org.owasp.dependencycheck.dependency.CvssV2;
import org.owasp.dependencycheck.dependency.CvssV3;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.dependency.VulnerableSoftwareBuilder;
import org.owasp.dependencycheck.dependency.naming.Identifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import us.springett.parsers.cpe.exceptions.CpeValidationException;
import us.springett.parsers.cpe.values.Part;

import org.sonatype.goodies.packageurl.PackageUrl;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.annotation.Nullable;

/**
 * Enrich dependency information from Sonatype OSS index.
 *
 * @since ???
 */
public class OssIndexAnalyzer extends AbstractAnalyzer {

    private static final Logger log = LoggerFactory.getLogger(OssIndexAnalyzer.class);

    public static final String REFERENCE_TYPE = "OSSINDEX";

    private OssindexClient client;
    
    private static final Pattern CVE_PATTERN = Pattern.compile("\\bCVE-\\d{4,4}-\\d{4,10}\\b");

    /**
     * Fetched reports.
     */
    private Map<PackageUrl, ComponentReport> reports;

    /**
     * Flag to indicate if fetching reports failed.
     */
    private boolean failed = false;

    /**
     * Lock to protect fetching state.
     */
    private final Object fetchMutex = new Object();

    @Override
    public String getName() {
        return "Sonatype OSS Index Analyzer";
    }

    @Override
    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.FINDING_ANALYSIS_PHASE2;
    }

    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_OSSINDEX_ENABLED;
    }

    /**
     * Run with parallel support.
     *
     * Fetch logic will however block all threads when state is established.
     */
    @Override
    public boolean supportsParallelProcessing() {
        return true;
    }

    @Override
    protected void prepareAnalyzer(final Engine engine) throws InitializationException {
        client = OssindexClientFactory.create(getSettings());
    }

    @Override
    protected void closeAnalyzer() throws Exception {
        if (client != null) {
            client.close();
        }
        client = null;
        reports = null;
        failed = false;
    }

    @Override
    protected void analyzeDependency(final Dependency dependency, final Engine engine) throws AnalysisException {
        if (client == null) {
            throw new IllegalStateException();
        }

        // batch request component-reports for all dependencies
        synchronized (fetchMutex) {
            if (!failed && reports == null) {
                try {
                    reports = requestReports(engine.getDependencies());
                } catch (Exception e) {
                    failed = true;
                    throw new AnalysisException("Failed to request component-reports", e);
                }
            }
        }

        // skip enrichment if we failed to fetch reports
        if (!failed) {
            enrich(dependency);
        }
    }

    /**
     * Helper to complain if unable to parse Package-URL.
     */
    @Nullable
    private PackageUrl parsePackageUrl(final String value) {
        try {
            return PackageUrl.parse(value);
        } catch (PackageUrl.InvalidException e) {
            log.warn("Invalid Package-URL: {}", value, e);
            return null;
        }
    }

    /**
     * Batch request component-reports for all dependencies.
     */
    private Map<PackageUrl, ComponentReport> requestReports(final Dependency[] dependencies) throws Exception {
        log.debug("Requesting component-reports for {} dependencies", dependencies.length);

        // create requests for each dependency which has a PURL identifier
        List<PackageUrl> packages = new ArrayList<>();
        for (Dependency dependency : dependencies) {
            for (Identifier id : dependency.getSoftwareIdentifiers()) {
                if (id instanceof PurlIdentifier) {
                    PackageUrl purl = parsePackageUrl(id.getValue());
                    if (purl != null) {
                        packages.add(purl);
                    }
                }
            }
        }

        // only attempt if we have been able to collect some packages
        if (!packages.isEmpty()) {
            return client.requestComponentReports(packages);
        }

        log.warn("Unable to determine Package-URL identifiers for {} dependencies", dependencies.length);
        return Collections.emptyMap();
    }

    /**
     * Attempt to enrich given dependency with vulnerability details from OSS
     * Index component-report.
     */
    private void enrich(final Dependency dependency) {
        log.debug("Enrich dependency: {}", dependency);

        for (Identifier id : dependency.getSoftwareIdentifiers()) {
            if (id instanceof PurlIdentifier) {
                log.debug("  Package: {} -> {}", id, id.getConfidence());

                PackageUrl purl = parsePackageUrl(id.getValue());
                if (purl != null) {
                    try {
                        ComponentReport report = reports.get(purl);
                        if (report == null) {
                            throw new IllegalStateException("Missing component-report for: " + purl);
                        }

                        // expose the URL to the package details for report generation
                        id.setUrl(report.getReference().toString());

                        for (ComponentReportVulnerability vuln : report.getVulnerabilities()) {
                            Vulnerability v = transform(report, vuln);
                            Vulnerability existing = dependency.getVulnerabilities().stream().filter(e->e.getName().equals(v.getName())).findFirst().orElse(null);
                            if (existing!=null) {
                                //TODO - can we enhance anything other than the references?
                                existing.getReferences().addAll(v.getReferences());
                            } else {
                                dependency.addVulnerability(v);
                            }
                        }
                    } catch (Exception e) {
                        log.warn("Failed to fetch component-report for: {}", purl, e);
                    }
                }
            }
        }
    }

    /**
     * Transform OSS Index component-report to ODC vulnerability.
     */
    private Vulnerability transform(final ComponentReport report, final ComponentReportVulnerability source) {
        Vulnerability result = new Vulnerability();
        result.setSource(Vulnerability.Source.OSSINDEX);
        
        if (source.getCve()!=null) {
            result.setName(source.getCve());    
        } else {
            String cve = null;
            if (source.getTitle()!=null) {
                Matcher matcher = CVE_PATTERN.matcher(source.getTitle());
                if (matcher.find()) {
                    cve = matcher.group();
                } else {
                    cve = source.getTitle();
                }
            }
            if (cve==null && source.getReference()!=null) {
                Matcher matcher = CVE_PATTERN.matcher(source.getReference().toString());
                if (matcher.find()) {
                    cve = matcher.group();
                }
            }
            result.setName(cve != null ? cve : source.getId());
        }
        result.setDescription(source.getDescription());
        result.addCwe(source.getCwe());

        float cvssScore = source.getCvssScore() != null ? source.getCvssScore() : -1;

        if (source.getCvssVector() != null) {
            // convert cvss details
            CvssVector cvssVector = CvssVectorFactory.create(source.getCvssVector());

            Map<String, String> metrics = cvssVector.getMetrics();
            if (cvssVector instanceof Cvss2Vector) {
                result.setCvssV2(new CvssV2(
                        cvssScore,
                        metrics.get(Cvss2Vector.ACCESS_VECTOR),
                        metrics.get(Cvss2Vector.ACCESS_COMPLEXITY),
                        metrics.get(Cvss2Vector.AUTHENTICATION),
                        metrics.get(Cvss2Vector.CONFIDENTIALITY_IMPACT),
                        metrics.get(Cvss2Vector.INTEGRITY_IMPACT),
                        metrics.get(Cvss2Vector.AVAILABILITY_IMPACT),
                        Cvss2Severity.of(cvssScore).name()
                ));
            } else if (cvssVector instanceof Cvss3Vector) {
                result.setCvssV3(new CvssV3(
                        metrics.get(Cvss3Vector.ATTACK_VECTOR),
                        metrics.get(Cvss3Vector.ATTACK_COMPLEXITY),
                        metrics.get(Cvss3Vector.PRIVILEGES_REQUIRED),
                        metrics.get(Cvss3Vector.USER_INTERACTION),
                        metrics.get(Cvss3Vector.SCOPE),
                        metrics.get(Cvss3Vector.CONFIDENTIALITY_IMPACT),
                        metrics.get(Cvss3Vector.INTEGRITY_IMPACT),
                        metrics.get(Cvss3Vector.AVAILABILITY_IMPACT),
                        cvssScore,
                        Cvss3Severity.of(cvssScore).name()
                ));
            } else {
                log.warn("Unsupported CVSS vector: {}", cvssVector);
                result.setUnscoredSeverity(Float.toString(cvssScore));
            }
        } else {
            log.debug("OSS has no vector for {}", result.getName());
            result.setUnscoredSeverity(Float.toString(cvssScore));
        }
        // generate a reference to the vulnerability details on OSS Index
        result.addReference(REFERENCE_TYPE, source.getTitle(), source.getReference().toString());

        // attach vulnerable software details as best we can
        PackageUrl purl = report.getCoordinates();
        try {
            VulnerableSoftwareBuilder builder = new VulnerableSoftwareBuilder()
                    .part(Part.APPLICATION)
                    .vendor(purl.getNamespaceAsString())
                    .product(purl.getName())
                    .version(purl.getVersion());

            // TODO: consider if we want/need to extract version-ranges to apply to vulnerable-software?
            VulnerableSoftware software = builder.build();
            result.addVulnerableSoftware(software);
            result.setMatchedVulnerableSoftware(software);
        } catch (CpeValidationException e) {
            log.warn("Unable to construct vulnerable-software for: {}", purl, e);
        }

        return result;
    }
}
