/*
 * This file is part of dependency-check-core.
 *
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
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

/**
 * An enumeration defining the phases of analysis.
 *
 * @author Jeremy Long
 */
public enum AnalysisPhase {

    /**
     * Initialization phase.
     * @implNote Bound analyzers are {@link ArchiveAnalyzer}
     */
    INITIAL,
    /**
     * Pre information collection phase.
     * @implNote Bound analyzers are {@link ElixirMixAuditAnalyzer},{@link RubyBundleAuditAnalyzer}
     */
    PRE_INFORMATION_COLLECTION,
    /**
     * Information collection phase.
     * @implNote Bound analyzers are
     * {@link ArtifactoryAnalyzer}
     * {@link AssemblyAnalyzer}
     * {@link AutoconfAnalyzer}
     * {@link CMakeAnalyzer}
     * {@link CentralAnalyzer}
     * {@link CarthageAnalyzer}
     * {@link CocoaPodsAnalyzer}
     * {@link ComposerLockAnalyzer}
     * {@link DartAnalyzer}
     * {@link FileNameAnalyzer}
     * {@link GolangDepAnalyzer}
     * {@link GolangModAnalyzer}
     * {@link JarAnalyzer}
     * {@link LibmanAnalyzer}
     * {@link MSBuildProjectAnalyzer}
     * {@link NexusAnalyzer}
     * {@link NodeAuditAnalyzer}
     * {@link NugetconfAnalyzer}
     * {@link NuspecAnalyzer}
     * {@link OpenSSLAnalyzer}
     * {@link PinnedMavenInstallAnalyzer}
     * {@link PipAnalyzer}
     * {@link PipfileAnalyzer}
     * {@link PipfilelockAnalyzer}
     * {@link PoetryAnalyzer}
     * {@link PythonDistributionAnalyzer}
     * {@link PythonPackageAnalyzer}
     * {@link RubyGemspecAnalyzer}
     * {@link RubyBundlerAnalyzer}
     * {@link SwiftPackageManagerAnalyzer}
     * {@link SwiftPackageResolvedAnalyzer}
     */
    INFORMATION_COLLECTION,
    /**
     * Information collection phase 2.
     * @implNote Bound analyzers are
     * {@link PEAnalyzer}
     */
    INFORMATION_COLLECTION2,
    /**
     * Post information collection phase 1.
     * @implNote Bound analyzers are
     * {@link DependencyMergingAnalyzer}
     */
    POST_INFORMATION_COLLECTION1,
    /**
     * Post information collection phase 2.
     * @implNote Bound analyzers are
     * {@link HintAnalyzer} (must run before {@link VersionFilterAnalyzer}, should run after {@link DependencyMergingAnalyzer})
     */
    POST_INFORMATION_COLLECTION2,
    /**
     * Post information collection phase 3.
     * @implNote Bound analyzers are
     * {@link VersionFilterAnalyzer}
     */
    POST_INFORMATION_COLLECTION3,
    /**
     * Pre identifier analysis phase.
     * @implNote Bound analyzers are
     * {@link NpmCPEAnalyzer} (must run in a separate phase from {@link CPEAnalyzer} due to singleton re-use)
     */
    PRE_IDENTIFIER_ANALYSIS,
    /**
     * Identifier analysis phase.
     * @implNote Bound analyzers are
     * {@link CPEAnalyzer}
     */
    IDENTIFIER_ANALYSIS,
    /**
     * Post identifier analysis phase.
     * @implNote Bound analyzers are
     * {@link CpeSuppressionAnalyzer}
     * {@link FalsePositiveAnalyzer}
     */
    POST_IDENTIFIER_ANALYSIS,
    /**
     * Pre finding analysis phase.
     * @implNote No analyzers bound to this phase
     */
    PRE_FINDING_ANALYSIS,
    /**
     * Finding analysis phase.
     * @implNote Bound analyzers are
     * {@link NodeAuditAnalyzer}
     * {@link NvdCveAnalyzer}
     * {@link PnpmAuditAnalyzer}
     * {@link RetireJsAnalyzer}
     * {@link YarnAuditAnalyzer}
     *
     */
    FINDING_ANALYSIS,
    /**
     * Finding analysis phase 2.
     * @implNote Bound analyzers are
     * {@link OssIndexAnalyzer}
     */
    FINDING_ANALYSIS_PHASE2,
    /**
     * Post analysis phase.
     * @implNote Bound analyzers are
     * {@link KnownExploitedVulnerabilityAnalyzer}
     * {@link VulnerabilitySuppressionAnalyzer}
     */
    POST_FINDING_ANALYSIS,
    /**
     * The final analysis phase.
     * @implNote Bound analyzers are
     * {@link DependencyBundlingAnalyzer}
     * {@link UnusedSuppressionRuleAnalyzer}
     */
    FINAL
}
