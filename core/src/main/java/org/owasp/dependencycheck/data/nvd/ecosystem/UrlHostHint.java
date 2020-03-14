package org.owasp.dependencycheck.data.nvd.ecosystem;

import org.owasp.dependencycheck.analyzer.NodeAuditAnalyzer;
import org.owasp.dependencycheck.analyzer.PythonPackageAnalyzer;
import org.owasp.dependencycheck.analyzer.RubyGemspecAnalyzer;

public enum UrlHostHint implements EcosystemHint {

    // note: all must be lowercase
    RUBY("ruby-lang.org", RubyGemspecAnalyzer.DEPENDENCY_ECOSYSTEM),
    PYTHON("python.org", PythonPackageAnalyzer.DEPENDENCY_ECOSYSTEM),
    DRUPAL("drupal.org", PythonPackageAnalyzer.DEPENDENCY_ECOSYSTEM),
    NODEJS("nodejs.org", NodeAuditAnalyzer.DEPENDENCY_ECOSYSTEM),
    NODE_SECURITY("nodesecurity.io", NodeAuditAnalyzer.DEPENDENCY_ECOSYSTEM);
    
    private final String keyword;
    
    private final String ecosystem;
    
    private UrlHostHint(String keyword, String ecosystem) {
        this.keyword = keyword;
        this.ecosystem = ecosystem;
    }

    @Override
    public String getEcosystem() {
        return ecosystem;
    }
    
    public String getKeyword() {
        return keyword;
    }

    @Override
    public EcosystemHintNature getNature() {
        return EcosystemHintNature.URL_HOST;
    }
    
    @Override
    public String getValue() {
        return getKeyword();
    }
    
}
