package org.owasp.dependencycheck.data.nvd.ecosystem;

import javax.annotation.concurrent.NotThreadSafe;

import org.owasp.dependencycheck.data.nvd.json.DefCveItem;

/**
 * 
 * Utility for mapping CVEs to their ecosystems.
 * <br><br>
 * Follows a best effort approach: 
 * <ul>
 *     <li>scans through the description for known keywords or file extensions; alternatively </li>
 *     <li>attempts looks at the reference-data URLs for known hosts or path / query strings.</li>
 * </ul>
 * This class is not thread safe and must be instantiated on a per-thread basis.
 * 
 */

@NotThreadSafe
public class CveEcosystemMapper {

    private final DescriptionEcosystemMapper descriptionEcosystemMapper = new DescriptionEcosystemMapper();
    
    private final UrlEcosystemMapper urlEcosystemMapper = new UrlEcosystemMapper();
    
    /**
     * Analyzes the description and assosiated URLs to determine if the vulnerability/software is
     * for a specific known ecosystem. The ecosystem can be used later for
     * filtering CPE matches.
     *
     * @param cve the item to be analyzed.
     * @return the ecosystem if one could be identified; otherwise <code>null</code>
     */
    
    public String getEcosystem(DefCveItem cve) {
        String ecosystem = descriptionEcosystemMapper.getEcosystem(cve);
        if(ecosystem != null) {
            return ecosystem;
        }
        return urlEcosystemMapper.getEcosystem(cve);
    }
    
}
