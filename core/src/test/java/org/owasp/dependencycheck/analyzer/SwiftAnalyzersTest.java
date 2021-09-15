package org.owasp.dependencycheck.analyzer;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertTrue;

import java.io.File;
import org.owasp.dependencycheck.dependency.EvidenceType;

/**
 * Unit tests for CocoaPodsAnalyzer and SwiftPackageManagerAnalyzer.
 *
 * @author Bianca Jiang
 * @author Jorge Mendes
 */
public class SwiftAnalyzersTest extends BaseTest {

    /**
     * The analyzer to test.
     */
    private CocoaPodsAnalyzer podsAnalyzer;
    private SwiftPackageManagerAnalyzer spmAnalyzer;
    private SwiftPackageResolvedAnalyzer sprAnalyzer;

    /**
     * Correctly setup the analyzer for testing.
     *
     * @throws Exception thrown if there is a problem
     */
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        podsAnalyzer = new CocoaPodsAnalyzer();
        podsAnalyzer.initialize(getSettings());
        podsAnalyzer.setFilesMatched(true);
        podsAnalyzer.prepare(null);

        spmAnalyzer = new SwiftPackageManagerAnalyzer();
        spmAnalyzer.initialize(getSettings());
        spmAnalyzer.setFilesMatched(true);
        spmAnalyzer.prepare(null);

        sprAnalyzer = new SwiftPackageResolvedAnalyzer();
        sprAnalyzer.initialize(getSettings());
        sprAnalyzer.setFilesMatched(true);
        sprAnalyzer.prepare(null);
    }

    /**
     * Cleanup the analyzer's temp files, etc.
     *
     * @throws Exception thrown if there is a problem
     */
    @After
    @Override
    public void tearDown() throws Exception {
        podsAnalyzer.close();
        podsAnalyzer = null;

        spmAnalyzer.close();
        spmAnalyzer = null;

        super.tearDown();
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
        assertThat(podsAnalyzer.accept(new File("Podfile.lock")), is(true));
    }

    /**
     * Test of supportsFiles method, of class SwiftPackageManagerAnalyzer.
     */
    @Test
    public void testSPMSupportsFiles() {
        assertThat(spmAnalyzer.accept(new File("Package.swift")), is(true));
        assertThat(sprAnalyzer.accept(new File("Package.resolved")), is(true));
    }

    /**
     * Test of analyze method, of class CocoaPodsAnalyzer.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    public void testCocoaPodsPodfileAnalyzer() throws AnalysisException {
        final Engine engine = new Engine(getSettings());
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this,
                "swift/cocoapods/Podfile.lock"));
        podsAnalyzer.analyze(result, engine);

        assertThat(engine.getDependencies().length, equalTo(9));
        assertThat(engine.getDependencies()[0].getName(), equalTo("Bolts"));
        assertThat(engine.getDependencies()[0].getVersion(), equalTo("1.9.0"));
        assertThat(engine.getDependencies()[1].getName(), equalTo("Bolts/AppLinks"));
        assertThat(engine.getDependencies()[1].getVersion(), equalTo("1.9.0"));
        assertThat(engine.getDependencies()[2].getName(), equalTo("Bolts/Tasks"));
        assertThat(engine.getDependencies()[2].getVersion(), equalTo("1.9.0"));
        assertThat(engine.getDependencies()[3].getName(), equalTo("FBSDKCoreKit"));
        assertThat(engine.getDependencies()[3].getVersion(), equalTo("4.33.0"));
        assertThat(engine.getDependencies()[4].getName(), equalTo("FBSDKLoginKit"));
        assertThat(engine.getDependencies()[4].getVersion(), equalTo("4.33.0"));
        assertThat(engine.getDependencies()[5].getName(), equalTo("FirebaseCore"));
        assertThat(engine.getDependencies()[5].getVersion(), equalTo("5.0.1"));
        assertThat(engine.getDependencies()[6].getName(), equalTo("GoogleToolboxForMac/Defines"));
        assertThat(engine.getDependencies()[6].getVersion(), equalTo("2.1.4"));
        assertThat(engine.getDependencies()[7].getName(), equalTo("GoogleToolboxForMac/NSData+zlib"));
        assertThat(engine.getDependencies()[7].getVersion(), equalTo("2.1.4"));
        assertThat(engine.getDependencies()[8].getName(), equalTo("OCMock"));
        assertThat(engine.getDependencies()[8].getVersion(), equalTo("3.4.1"));
    }

    @Test
    public void testCocoaPodsPodspecAnalyzer() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this,
                "swift/cocoapods/EasyPeasy.podspec"));
        podsAnalyzer.analyze(result, null);
        final String vendorString = result.getEvidence(EvidenceType.VENDOR).toString();

        assertThat(vendorString, containsString("Carlos Vidal"));
        assertThat(vendorString, containsString("https://github.com/nakiostudio/EasyPeasy"));
        assertThat(result.getEvidence(EvidenceType.PRODUCT).toString(), containsString("EasyPeasy"));
        assertThat(result.getEvidence(EvidenceType.VERSION).toString(), containsString("0.2.3"));
        assertThat(result.getName(), equalTo("EasyPeasy"));
        assertThat(result.getVersion(), equalTo("0.2.3"));
        assertThat(result.getDisplayFileName(), equalTo("EasyPeasy:0.2.3"));
        assertThat(result.getLicense(), containsString("MIT"));
        assertThat(result.getEcosystem(), equalTo(CocoaPodsAnalyzer.DEPENDENCY_ECOSYSTEM));
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

        assertThat(result.getEvidence(EvidenceType.PRODUCT).toString(), containsString("Gloss"));
        assertThat(result.getName(), equalTo("Gloss"));
        //TODO: when version processing is added, update the expected name.
        assertThat(result.getDisplayFileName(), equalTo("Gloss"));
        assertThat(result.getEcosystem(), equalTo(SwiftPackageManagerAnalyzer.DEPENDENCY_ECOSYSTEM));
    }

    @Test
    public void testSPMResolvedAnalyzer() throws AnalysisException {
        final Engine engine = new Engine(getSettings());
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this,
                "swift/spm/Package.resolved"));
        sprAnalyzer.analyze(result, engine);

        assertThat(engine.getDependencies().length, equalTo(3));
        assertThat(engine.getDependencies()[0].getName(), equalTo("Alamofire"));
        assertThat(engine.getDependencies()[0].getVersion(), equalTo("5.4.3"));
        assertThat(engine.getDependencies()[1].getName(), equalTo("AlamofireImage"));
        assertThat(engine.getDependencies()[1].getVersion(), equalTo("4.2.0"));
        assertThat(engine.getDependencies()[2].getName(), equalTo("Facebook"));
        assertThat(engine.getDependencies()[2].getVersion(), equalTo("9.3.0"));
    }

    @Test
    public void testIsEnabledIsTrueByDefault() {
        assertTrue(spmAnalyzer.isEnabled());
        assertTrue(sprAnalyzer.isEnabled());
    }
}
