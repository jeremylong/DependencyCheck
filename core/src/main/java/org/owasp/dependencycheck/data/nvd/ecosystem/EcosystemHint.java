package org.owasp.dependencycheck.data.nvd.ecosystem;

public interface EcosystemHint {

    EcosystemHintNature getNature();
    
    String getEcosystem();

    String getValue();

}
