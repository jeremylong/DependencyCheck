package org.owasp.dependencycheck.data.nvdcve;

import java.util.List;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.owasp.dependencycheck.analyzer.AbstractNpmAnalyzer;
import org.owasp.dependencycheck.analyzer.CMakeAnalyzer;
import org.owasp.dependencycheck.analyzer.ComposerLockAnalyzer;
import org.owasp.dependencycheck.analyzer.JarAnalyzer;
import org.owasp.dependencycheck.analyzer.NodeAuditAnalyzer;
import org.owasp.dependencycheck.analyzer.PythonPackageAnalyzer;
import org.owasp.dependencycheck.analyzer.RubyBundleAuditAnalyzer;
import org.owasp.dependencycheck.analyzer.RubyGemspecAnalyzer;
import org.owasp.dependencycheck.data.nvd.json.DefCveItem;
import org.owasp.dependencycheck.data.nvd.json.Reference;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;

/**
 * 
 * Utility for processing {@linkplain DefCveItem} in order to extract key values like textual description and ecosystem type. 
 *
 */

public class CveItemOperator {
    
    public String extractDescription(DefCveItem cve) {
        return cve.getCve().getDescription().getDescriptionData().stream().filter((desc)
                -> "en".equals(desc.getLang())).map(d
                -> d.getValue()).collect(Collectors.joining(" "));
    }
    
    /**
     * Analyzes the description to determine if the vulnerability/software is
     * for a specific known ecosystem. The ecosystem can be used later for
     * filtering CPE matches.
     *
     * @param description the description to analyze
     * @return the ecosystem if one could be identified; otherwise
     * <code>null</code>
     */
    public String extractBaseEcosystem(DefCveItem cve, String description) {
        if (description == null) {
            return extractBaseEcosystemFromReferences(cve);
        }
        int idx = StringUtils.indexOfIgnoreCase(description, ".php");
        if ((idx > 0 && (idx + 4 == description.length() || !Character.isLetterOrDigit(description.charAt(idx + 4))))
                || StringUtils.containsIgnoreCase(description, "wordpress")
                || StringUtils.containsIgnoreCase(description, "drupal")
                || StringUtils.containsIgnoreCase(description, "joomla")
                || StringUtils.containsIgnoreCase(description, "moodle")
                || StringUtils.containsIgnoreCase(description, "typo3")) {
            return ComposerLockAnalyzer.DEPENDENCY_ECOSYSTEM;
        }
        if (StringUtils.containsIgnoreCase(description, " npm ")
                || (StringUtils.containsIgnoreCase(description, "node module") && StringUtils.containsIgnoreCase(description, ".js"))
                || StringUtils.containsIgnoreCase(description, " node.js")) {
            return AbstractNpmAnalyzer.NPM_DEPENDENCY_ECOSYSTEM;
        }
        idx = StringUtils.indexOfIgnoreCase(description, ".pm");
        if (idx > 0 && (idx + 3 == description.length() || !Character.isLetterOrDigit(description.charAt(idx + 3)))) {
            return "perl";
        } else {
            idx = StringUtils.indexOfIgnoreCase(description, ".pl");
            if (idx > 0 && (idx + 3 == description.length() || !Character.isLetterOrDigit(description.charAt(idx + 3)))) {
                return "perl";
            }
        }
        idx = StringUtils.indexOfIgnoreCase(description, ".java");
        if (idx > 0 && (idx + 5 == description.length() || !Character.isLetterOrDigit(description.charAt(idx + 5)))) {
            return JarAnalyzer.DEPENDENCY_ECOSYSTEM;
        } else {
            idx = StringUtils.indexOfIgnoreCase(description, ".jsp");
            if (idx > 0 && (idx + 4 == description.length() || !Character.isLetterOrDigit(description.charAt(idx + 4)))) {
                return JarAnalyzer.DEPENDENCY_ECOSYSTEM;
            }
        }
        if (StringUtils.containsIgnoreCase(description, " grails ")) {
            return JarAnalyzer.DEPENDENCY_ECOSYSTEM;
        }

        idx = StringUtils.indexOfIgnoreCase(description, ".rb");
        if (idx > 0 && (idx + 3 == description.length() || !Character.isLetterOrDigit(description.charAt(idx + 3)))) {
            return RubyBundleAuditAnalyzer.DEPENDENCY_ECOSYSTEM;
        }
        if (StringUtils.containsIgnoreCase(description, "ruby gem")) {
            return RubyBundleAuditAnalyzer.DEPENDENCY_ECOSYSTEM;
        }

        idx = StringUtils.indexOfIgnoreCase(description, ".py");
        if ((idx > 0 && (idx + 3 == description.length() || !Character.isLetterOrDigit(description.charAt(idx + 3))))
                || StringUtils.containsIgnoreCase(description, "django")) {
            return PythonPackageAnalyzer.DEPENDENCY_ECOSYSTEM;
        }

        if (StringUtils.containsIgnoreCase(description, "buffer overflow")
                && !StringUtils.containsIgnoreCase(description, "android")) {
            return CMakeAnalyzer.DEPENDENCY_ECOSYSTEM;
        }
        idx = StringUtils.indexOfIgnoreCase(description, ".c");
        if (idx > 0 && (idx + 2 == description.length() || !Character.isLetterOrDigit(description.charAt(idx + 2)))) {
            return CMakeAnalyzer.DEPENDENCY_ECOSYSTEM;
        } else {
            idx = StringUtils.indexOfIgnoreCase(description, ".cpp");
            if (idx > 0 && (idx + 4 == description.length() || !Character.isLetterOrDigit(description.charAt(idx + 4)))) {
                return CMakeAnalyzer.DEPENDENCY_ECOSYSTEM;
            } else {
                idx = StringUtils.indexOfIgnoreCase(description, ".h");
                if (idx > 0 && (idx + 2 == description.length() || !Character.isLetterOrDigit(description.charAt(idx + 2)))) {
                    return CMakeAnalyzer.DEPENDENCY_ECOSYSTEM;
                }
            }
        }
        return extractBaseEcosystemFromReferences(cve);
    }
    
    protected String extractBaseEcosystemFromReferences(DefCveItem cve) {
        for (Reference r : cve.getCve().getReferences().getReferenceData()) {
            if (r.getUrl().contains("elixir-security-advisories")) {
                return "elixir";
            } else if (r.getUrl().contains("ruby-lang.org")) {
                return  RubyGemspecAnalyzer.DEPENDENCY_ECOSYSTEM;
            } else if (r.getUrl().contains("python.org")) {
                return  PythonPackageAnalyzer.DEPENDENCY_ECOSYSTEM;
            } else if (r.getUrl().contains("drupal.org")) {
                return  PythonPackageAnalyzer.DEPENDENCY_ECOSYSTEM;
            } else if (r.getUrl().contains("npm")) {
                return  NodeAuditAnalyzer.DEPENDENCY_ECOSYSTEM;
            } else if (r.getUrl().contains("nodejs.org")) {
                return  NodeAuditAnalyzer.DEPENDENCY_ECOSYSTEM;
            } else if (r.getUrl().contains("nodesecurity.io")) {
                return  NodeAuditAnalyzer.DEPENDENCY_ECOSYSTEM;
            } else if (r.getUrl().contains("rustsec.org")) {
                return "rust";
            }
        }
        return null;
    }
    
    /**
     * Attempts to determine the ecosystem based on the vendor, product and
     * targetSw.
     *
     * @param baseEcosystem the base ecosystem
     * @param vendor the vendor
     * @param product the product
     * @param targetSw the target software
     * @return the ecosystem if one is identified
     */
    private String extractEcosystem(String baseEcosystem, String vendor, String product, String targetSw) {
        if ("ibm".equals(vendor) && "java".equals(product)) {
            return "c/c++";
        }
        if ("oracle".equals(vendor) && "vm".equals(product)) {
            return "c/c++";
        }
        if ("*".equals(targetSw) || baseEcosystem != null) {
            return baseEcosystem;
        }
        return targetSw;
    }

    public String extractEcosystem(String baseEcosystem, VulnerableSoftware parsedCpe) {
        return extractEcosystem(baseEcosystem, parsedCpe.getVendor(), parsedCpe.getProduct(), parsedCpe.getTargetSw());
    }
    
    public boolean isRejected(String description) {
        return description.startsWith("** REJECT **");
    }

}
