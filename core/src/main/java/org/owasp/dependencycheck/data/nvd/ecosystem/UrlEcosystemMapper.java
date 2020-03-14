package org.owasp.dependencycheck.data.nvd.ecosystem;

import java.util.TreeMap;

import javax.annotation.concurrent.NotThreadSafe;

import org.owasp.dependencycheck.data.nvd.json.DefCveItem;
import org.owasp.dependencycheck.data.nvd.json.Reference;

import com.hankcs.algorithm.AhoCorasickDoubleArrayTrie;
import com.hankcs.algorithm.AhoCorasickDoubleArrayTrie.Hit;

@NotThreadSafe
public class UrlEcosystemMapper {

    protected static final TreeMap<String, String> map;

    static {
        map = new TreeMap<String, String>();
        for(UrlHostHint urlHostHint : UrlHostHint.values()) {
            map.put(urlHostHint.getValue(), urlHostHint.getEcosystem());
        }
        for(UrlPathHint urlPathHint : UrlPathHint.values()) {
            map.put(urlPathHint.getValue(), urlPathHint.getEcosystem());
        }
    }
    
    protected AhoCorasickDoubleArrayTrie<String> search;
    
    public UrlEcosystemMapper() {
        search = new AhoCorasickDoubleArrayTrie<String>();
        search.build(map);
    }

    public String getEcosystem(DefCveItem cve) {
        for (Reference r : cve.getCve().getReferences().getReferenceData()) {
            
            Hit<String> ecosystem = search.findFirst(r.getUrl());
            if(ecosystem != null) {
                return ecosystem.value;
            }
        }    
        return null;
    }
}
