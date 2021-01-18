package org.owasp.dependencycheck.analyzer;

import java.io.File;

import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class YarnAuditAnalyzerTest extends BaseTest {

    @Test
    public void testGetName() {
        YarnAuditAnalyzer analyzer = new YarnAuditAnalyzer();
        assertThat(analyzer.getName(), is("Yarn Audit Analyzer"));
    }

    @Test
    public void testSupportsFiles() {
        YarnAuditAnalyzer analyzer = new YarnAuditAnalyzer();
        assertThat(analyzer.accept(new File("package-lock.json")), is(false));
        assertThat(analyzer.accept(new File("npm-shrinkwrap.json")), is(false));
        assertThat(analyzer.accept(new File("yarn.lock")), is(true));
        assertThat(analyzer.accept(new File("package.json")), is(false));
    }
}
