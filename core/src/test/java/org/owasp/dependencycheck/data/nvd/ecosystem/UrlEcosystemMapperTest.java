package org.owasp.dependencycheck.data.nvd.ecosystem;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

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

    @Test
    public void testGetEcosystemMustHandleNullCveReferences() {
        // Given
        UrlEcosystemMapper mapper = new UrlEcosystemMapper();

        CVEJSON40Min11 cve = new CVEJSON40Min11();

        DefCveItem cveItem = new DefCveItem();
        cveItem.setCve(cve);

        // When
        String output = mapper.getEcosystem(cveItem);

        // Then
        assertNull(output);
    }

    @Test
    public void testGetEcosystemMustHandleNullCve() {
        // Given
        UrlEcosystemMapper mapper = new UrlEcosystemMapper();

        DefCveItem cveItem = new DefCveItem();

        // When
        String output = mapper.getEcosystem(cveItem);

        // Then
        assertNull(output);
    }

    @Test
    public void testGetEcosystemMustHandleNullCveItem() {
        // Given
        UrlEcosystemMapper mapper = new UrlEcosystemMapper();

        // When
        String output = mapper.getEcosystem(null);

        // Then
        assertNull(output);
    }
}
