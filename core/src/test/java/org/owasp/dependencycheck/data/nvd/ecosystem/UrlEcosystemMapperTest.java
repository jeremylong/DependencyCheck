package org.owasp.dependencycheck.data.nvd.ecosystem;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.owasp.dependencycheck.analyzer.PythonPackageAnalyzer;
import org.owasp.dependencycheck.data.nvd.json.CVEJSON40Min11;
import org.owasp.dependencycheck.data.nvd.json.DefCveItem;
import org.owasp.dependencycheck.data.nvd.json.Reference;
import org.owasp.dependencycheck.data.nvd.json.References;

public class UrlEcosystemMapperTest {

    @Test
    public void testUrlHostEcosystemMapper() {
        
        UrlEcosystemMapper mapper = new UrlEcosystemMapper();
        
        assertEquals(PythonPackageAnalyzer.DEPENDENCY_ECOSYSTEM, mapper.getEcosystem(asCve("https://python.org/path")));
    }

    private DefCveItem asCve(String url) {
        DefCveItem defCveItem = new DefCveItem();
        
        References references = new References();
        
        Reference reference = new Reference();
        reference.setUrl(url);
        
        references.getReferenceData().add(reference);
        
        CVEJSON40Min11 cve = new CVEJSON40Min11();
        cve.setReferences(references);
        
        defCveItem.setCve(cve);
        
        return defCveItem;
    }
}
