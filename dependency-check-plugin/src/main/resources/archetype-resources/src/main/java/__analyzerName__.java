/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ${package};

import java.io.File;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.AnalysisPhase;
import org.owasp.dependencycheck.analyzer.Analyzer;
import org.owasp.dependencycheck.analyzer.FileTypeAnalyzer;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.Settings;

/**
 * An OWASP dependency-check plug-in example. If you are not implementing a
 * FileTypeAnalyzer, simple remove the annotation and the accept() method.
 */
public class ${analyzerName} implements Analyzer, FileTypeAnalyzer {

    /**
     * The Logger for use throughout the ${analyzerName}.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(${analyzerName}.class);

    /**
     * <p>
     * Method implementation for the FileTypeAnalyzer; if not implementing a
     * file type analyzer this method can be removed.</p>
     * <p>
     * Determines if the analyzer can process the given file.</p>
     *
     * @param pathname the path to the file
     * @return <code>true</code> if the analyzer can process the file; otherwise
     * <code>false</code>
     */
    @Override
    public boolean accept(File pathname) {
        return true;
    }

    /**
     * Analyzes the given dependency. The analysis could be anything from
     * identifying an Identifier for the dependency, to finding vulnerabilities,
     * etc. Additionally, if the analyzer collects enough information to add a
     * description or license information for the dependency it should be added.
     *
     * @param dependency a dependency to analyze.
     * @param engine the engine that is scanning the dependencies - this is
     * useful if we need to check other dependencies
     * @throws AnalysisException is thrown if there is an error analyzing the
     * dependency file
     */
    @Override
    public void analyze(Dependency dependency, Engine engine) throws AnalysisException {
        if (enabled) {
            //TODO implement analyze
        }
    }

    /**
     * Returns the name of the analyzer.
     *
     * @return the name of the analyzer.
     */
    @Override
    public String getName() {
        return "${analyzerName}";
    }

    /**
     * Returns the phase that the analyzer is intended to run in.
     *
     * @return the phase that the analyzer is intended to run in.
     */
    @Override
    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.INFORMATION_COLLECTION;
    }

    /**
     * The initialize method is called just after instantiation of the object.
     *
     * @param settings a reference to the configured settings
     */
    @Override
    public void initialize(Settings settings) {
        //TODO implement initialize
    }

    /**
     * The prepare method is called once just prior to repeated calls to
     * analyze.
     *
     * @param engine a reference to the engine
     * @throws InitializationException thrown when the analyzer cannot be
     * initialized
     */
    @Override
    public void prepare(Engine engine) throws InitializationException {
        //TODO implement prepare
    }

    /**
     * The close method is called after all of the dependencies have been
     * analyzed.
     *
     * @throws Exception is thrown if an exception occurs closing the analyzer.
     */
    @Override
    public void close() throws Exception {

    }

    /**
     * Returns whether multiple instances of the same type of analyzer can run
     * in parallel. If the analyzer does not support parallel processing it is
     * generally best to also mark the analyze(Dependency,Engine) as synchronized.
     *
     * @return {@code true} if the analyzer supports parallel processing,
     * {@code false} else
     */
    @Override
    public boolean supportsParallelProcessing() {
        return true;
    }

    /**
     * Flag indicating whether or not the analyzer is enabled.
     */
    private boolean enabled = true;

    /**
     * Returns whether or not the analyzer is enabled.
     *
     * @return whether or not the analyzer is enabled
     */
    @Override
    public boolean isEnabled() {
        return enabled;
    }
}
