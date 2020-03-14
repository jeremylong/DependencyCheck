package org.owasp.dependencycheck.data.nvd.ecosystem;

import org.owasp.dependencycheck.analyzer.CMakeAnalyzer;
import org.owasp.dependencycheck.analyzer.ComposerLockAnalyzer;
import org.owasp.dependencycheck.analyzer.JarAnalyzer;
import org.owasp.dependencycheck.analyzer.PythonPackageAnalyzer;
import org.owasp.dependencycheck.analyzer.RubyBundleAuditAnalyzer;

public enum FileExtensionHint implements EcosystemHint {

    // note: all must be lowercase
    PHP(".php", ComposerLockAnalyzer.DEPENDENCY_ECOSYSTEM),
    PERL_PM(".pm", "perl"),
    PERL_PL(".pl", "perl"),
    JAR_JAVA(".java", JarAnalyzer.DEPENDENCY_ECOSYSTEM),
    JAR_JSP(".jsp", JarAnalyzer.DEPENDENCY_ECOSYSTEM),
    JAR_RUBY(".rb", RubyBundleAuditAnalyzer.DEPENDENCY_ECOSYSTEM),
    PYTON(".py", PythonPackageAnalyzer.DEPENDENCY_ECOSYSTEM),
    CMAKE_CPP(".cpp", CMakeAnalyzer.DEPENDENCY_ECOSYSTEM),
    CMAKE_C(".c", CMakeAnalyzer.DEPENDENCY_ECOSYSTEM),
    CMAKE_H(".h", CMakeAnalyzer.DEPENDENCY_ECOSYSTEM);
    
    private final String extension;

    private final String ecosystem;

    private FileExtensionHint(String extension, String ecosystem) {
        this.extension = extension;
        this.ecosystem = ecosystem;
    }

    @Override
    public String getEcosystem() {
        return ecosystem;
    }

    public String getExtension() {
        return extension;
    }

    @Override
    public EcosystemHintNature getNature() {
        return EcosystemHintNature.FILE_EXTENSION;
    }

    @Override
    public String getValue() {
        return getExtension();
    }
}
