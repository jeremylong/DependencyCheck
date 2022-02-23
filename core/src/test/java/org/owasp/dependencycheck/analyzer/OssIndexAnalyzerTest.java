package org.owasp.dependencycheck.analyzer;

import static org.junit.Assert.assertTrue;

import java.util.Collections;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.naming.Identifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.utils.Settings;

import com.github.packageurl.MalformedPackageURLException;

public class OssIndexAnalyzerTest extends BaseTest {

    @Test
    public void should_enrich_be_included_in_mutex_to_prevent_NPE()
            throws AnalysisException, MalformedPackageURLException {

        // Given
        OssIndexAnalyzer analyzer = new SproutOssIndexAnalyzer();


        Identifier identifier = new PurlIdentifier("maven", "test", "test", "1.0",
                Confidence.HIGHEST);

        Dependency dependency = new Dependency();
        dependency.addSoftwareIdentifier(identifier);
        Settings settings = getSettings();
        Engine engine = new Engine(settings);
        engine.setDependencies(Collections.singletonList(dependency));

        analyzer.initialize(settings);

        String expectedOutput = "https://ossindex.sonatype.org/component/pkg:maven/test/test@1.0";

        // When
        analyzer.analyzeDependency(dependency, engine);

        // Then
        assertTrue(identifier.getUrl().startsWith(expectedOutput));
    }

    /*
     * This action is inspired by the sprout method technique displayed in
     * "Michael Feathers - Working Effectively with Legacy code".
     *
     * We want to trigger a race condition between a call to
     * OssIndexAnalyzer.closeAnalyzer() and OssIndexAnalyzer.enrich().
     *
     * The last method access data from the "reports" field while
     * closeAnalyzer() erase the reference. If enrich() is not included in
     * the "FETCH_MUTIX" synchronized statement, we can trigger a
     * NullPointeException in a multithreaded environment, which can happen
     * due to the usage of java.util.concurrent.Future.
     *
     * We want to make sure enrich() will be able to set the url of an
     * identifier and enrich it.
     */
    static final class SproutOssIndexAnalyzer extends OssIndexAnalyzer {
        @Override
        void enrich(Dependency dependency) {
            ExecutorService executor = Executors.newSingleThreadExecutor();
            executor.execute(() -> {
                try {
                    this.closeAnalyzer();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
            super.enrich(dependency);
        }
    }
}
