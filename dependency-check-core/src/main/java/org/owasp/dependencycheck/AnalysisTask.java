package org.owasp.dependencycheck;

import org.owasp.dependencycheck.analyzer.Analyzer;
import org.owasp.dependencycheck.analyzer.FileTypeAnalyzer;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.Callable;

class AnalysisTask implements Callable<Void> {

    private static final Logger LOGGER = LoggerFactory.getLogger(AnalysisTask.class);

    private final Analyzer analyzer;
    private final Dependency dependency;
    private final Engine engine;
    private final List<Throwable> exceptions;

    AnalysisTask(Analyzer analyzer, Dependency dependency, Engine engine, List<Throwable> exceptions) {
        this.analyzer = analyzer;
        this.dependency = dependency;
        this.engine = engine;
        this.exceptions = exceptions;
    }

    @Override
    public Void call() throws Exception {
        Settings.initialize();

        if (shouldAnalyze()) {
            LOGGER.debug("Begin Analysis of '{}' ({})", dependency.getActualFilePath(), analyzer.getName());
            try {
                analyzer.analyze(dependency, engine);
            } catch (AnalysisException ex) {
                LOGGER.warn("An error occurred while analyzing '{}' ({}).", dependency.getActualFilePath(), analyzer.getName());
                LOGGER.debug("", ex);
                exceptions.add(ex);
            } catch (Throwable ex) {
                LOGGER.warn("An unexpected error occurred during analysis of '{}' ({}): {}",
                        dependency.getActualFilePath(), analyzer.getName(), ex.getMessage());
                LOGGER.debug("", ex);
                exceptions.add(ex);
            }
        }

        return null;
    }

    private boolean shouldAnalyze() {
        if (analyzer instanceof FileTypeAnalyzer) {
            final FileTypeAnalyzer fAnalyzer = (FileTypeAnalyzer) analyzer;
            return fAnalyzer.accept(dependency.getActualFile());
        }

        return true;
    }
}
