package org.owasp.dependencycheck.analyzer;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.io.File;

/**
 * Unit tests for CocoaPodsAnalyzer.
 *
 * @author Bianca Jiang
 */
public class SwiftAnalyzersTest extends BaseTest {

    /**
     * The analyzer to test.
     */
    private CocoaPodsAnalyzer podsAnalyzer;
    private SwiftPackageManagerAnalyzer spmAnalyzer;

    /**
     * Correctly setup the analyzer for testing.
     *
     * @throws Exception thrown if there is a problem
     */
    @Before
    public void setUp() throws Exception {
        podsAnalyzer = new CocoaPodsAnalyzer();
        podsAnalyzer.setFilesMatched(true);
        podsAnalyzer.initialize();

        spmAnalyzer = new SwiftPackageManagerAnalyzer();
        spmAnalyzer.setFilesMatched(true);
        spmAnalyzer.initialize();
    }

    /**
     * Cleanup the analyzer's temp files, etc.
     *
     * @throws Exception thrown if there is a problem
     */
    @After
    public void tearDown() throws Exception {
        podsAnalyzer.close();
        podsAnalyzer = null;

        spmAnalyzer.close();
        spmAnalyzer = null;
    }

    /**
     * Test of getName method, of class CocoaPodsAnalyzer.
     */
    @Test
    public void testPodsGetName() {
        assertThat(podsAnalyzer.getName(), is("CocoaPods Package Analyzer"));
    }

    /**
     * Test of getName method, of class SwiftPackageManagerAnalyzer.
     */
    @Test
    public void testSPMGetName() {
        assertThat(spmAnalyzer.getName(), is("SWIFT Package Manager Analyzer"));
    }

    /**
     * Test of supportsFiles method, of class CocoaPodsAnalyzer.
     */
    @Test
    public void testPodsSupportsFiles() {
        assertThat(podsAnalyzer.accept(new File("test.podspec")), is(true));
    }

    /**
     * Test of supportsFiles method, of class SwiftPackageManagerAnalyzer.
     */
    @Test
    public void testSPMSupportsFiles() {
        assertThat(spmAnalyzer.accept(new File("Package.swift")), is(true));
    }

    /**
     * Test of analyze method, of class CocoaPodsAnalyzer.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    public void testCocoaPodsAnalyzer() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this,
                "swift/cocoapods/EasyPeasy.podspec"));
        podsAnalyzer.analyze(result, null);
        final String vendorString = result.getVendorEvidence().toString();

        assertThat(vendorString, containsString("Carlos Vidal"));
        assertThat(vendorString, containsString("https://github.com/nakiostudio/EasyPeasy"));
        assertThat(vendorString, containsString("MIT"));
        assertThat(result.getProductEvidence().toString(), containsString("EasyPeasy"));
        assertThat(result.getVersionEvidence().toString(), containsString("0.2.3"));
    }

    /**
     * Test of analyze method, of class SwiftPackageManagerAnalyzer.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    public void testSPMAnalyzer() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this,
                "swift/Gloss/Package.swift"));
        spmAnalyzer.analyze(result, null);

        assertThat(result.getProductEvidence().toString(), containsString("Gloss"));
    }
}
