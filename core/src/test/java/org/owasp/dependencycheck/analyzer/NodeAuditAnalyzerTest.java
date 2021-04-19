package org.owasp.dependencycheck.analyzer;

import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import java.io.File;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class NodeAuditAnalyzerTest extends BaseTest {

    @Test
    public void testGetName() {
        NodeAuditAnalyzer analyzer = new NodeAuditAnalyzer();
        assertThat(analyzer.getName(), is("Node Audit Analyzer"));
    }

    @Test
    public void testSupportsFiles() {
        NodeAuditAnalyzer analyzer = new NodeAuditAnalyzer();
        assertThat(analyzer.accept(new File("package-lock.json")), is(true));
        assertThat(analyzer.accept(new File("npm-shrinkwrap.json")), is(true));
        assertThat(analyzer.accept(new File("yarn.lock")), is(false));
        assertThat(analyzer.accept(new File("package.json")), is(false));
    }
}
