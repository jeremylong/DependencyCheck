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
public class CocoaPodsAnalyzerTest extends BaseTest {

    /**
     * The analyzer to test.
     */
	CocoaPodsAnalyzer analyzer;

    /**
     * Correctly setup the analyzer for testing.
     *
     * @throws Exception thrown if there is a problem
     */
    @Before
    public void setUp() throws Exception {
        analyzer = new CocoaPodsAnalyzer();
        analyzer.setFilesMatched(true);
        analyzer.initialize();
    }

    /**
     * Cleanup the analyzer's temp files, etc.
     *
     * @throws Exception thrown if there is a problem
     */
    @After
    public void tearDown() throws Exception {
        analyzer.close();
        analyzer = null;
    }

    /**
     * Test of getName method, of class PythonDistributionAnalyzer.
     */
    @Test
    public void testGetName() {
        assertThat(analyzer.getName(), is("CocoaPods Package Analyzer"));
    }

    /**
     * Test of supportsExtension method, of class PythonDistributionAnalyzer.
     */
    @Test
    public void testSupportsFiles() {
        assertThat(analyzer.accept(new File("test.podspec")), is(true));
    }

    /**
     * Test of inspect method, of class PythonDistributionAnalyzer.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    public void testAnalyzePackageJson() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this,
                "swift/cocoapods/EasyPeasy.podspec"));
        analyzer.analyze(result, null);
        final String vendorString = result.getVendorEvidence().toString();
        
        assertThat(vendorString, containsString("Carlos Vidal"));
        assertThat(vendorString, containsString("https://github.com/nakiostudio/EasyPeasy"));
        assertThat(vendorString, containsString("MIT"));
        assertThat(result.getProductEvidence().toString(), containsString("EasyPeasy"));
        assertThat(result.getVersionEvidence().toString(), containsString("0.2.3"));
        
        System.out.println("vendor: " + vendorString);
        System.out.println("product: " + result.getProductEvidence().toString());
        System.out.println("version: " + result.getVersionEvidence().toString());
    }
}
