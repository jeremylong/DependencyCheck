package org.owasp.dependencycheck.data.nvd.ecosystem;

import org.owasp.dependencycheck.analyzer.AbstractNpmAnalyzer;

public enum UrlPathHint implements EcosystemHint {

    // note: all must be lowercase
    ELIXIR("elixir-security-advisories", "elixir"),
    NPM("npm", AbstractNpmAnalyzer.NPM_DEPENDENCY_ECOSYSTEM);
    
    private final String keyword;
    
    private final String ecosystem;
    
    private UrlPathHint(String keyword, String ecosystem) {
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
        return EcosystemHintNature.URL_PATH;
    }
    
    @Override
    public String getValue() {
        return getKeyword();
    }
    
}
