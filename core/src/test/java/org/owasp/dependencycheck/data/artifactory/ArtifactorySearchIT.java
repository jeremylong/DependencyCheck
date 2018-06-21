package org.owasp.dependencycheck.data.artifactory;

import org.junit.Ignore;
import org.junit.Test;
import org.owasp.dependencycheck.data.nexus.MavenArtifact;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.Settings;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

@Ignore
public class ArtifactorySearchIT {


    @Test
    public void testWithRealInstanceUsingBearerToken() throws IOException {
        // Given
        Dependency dependency = new Dependency();
        dependency.setSha1sum("c5b4c491aecb72e7c32a78da0b5c6b9cda8dee0f");
        dependency.setSha256sum("512b4bf6927f4864acc419b8c5109c23361c30ed1f5798170248d33040de068e");
        dependency.setMd5sum("2d1dd0fc21ee96bccfab4353d5379649");

        final Settings settings = new Settings();
        settings.setString(Settings.KEYS.ANALYZER_ARTIFACTORY_URL, "https://artifactory.techno.ingenico.com/artifactory");

        // See org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_ARTIFACTORY_BEARER_TOKEN .for how to generate a bearer token using the API
        settings.setString(Settings.KEYS.ANALYZER_ARTIFACTORY_BEARER_TOKEN, "yourBearerToken");
        final ArtifactorySearch artifactorySearch = new ArtifactorySearch(settings);
        // When
        final List<MavenArtifact> mavenArtifacts = artifactorySearch.search(dependency);

        // Then

        assertEquals(1, mavenArtifacts.size());
        final MavenArtifact artifact = mavenArtifacts.get(0);
        assertEquals("com.google.code.gson", artifact.getGroupId());
        assertEquals("gson", artifact.getArtifactId());
        assertEquals("2.8.5", artifact.getVersion());
        assertEquals("https://artifactory.techno.ingenico.com/artifactory/repo1-cache/com/google/code/gson/gson/2.8.5/gson-2.8.5-sources.jar", artifact.getArtifactUrl());
        assertEquals("https://artifactory.techno.ingenico.com/artifactory/repo1-cache/com/google/code/gson/gson/2.8.5/gson-2.8.5.pom", artifact.getPomUrl());
    }

    @Test
    public void testWithRealInstanceAnonymous() throws IOException {
        // Given
        Dependency dependency = new Dependency();
        dependency.setSha1sum("c5b4c491aecb72e7c32a78da0b5c6b9cda8dee0f");

        final Settings settings = new Settings();
        settings.setString(Settings.KEYS.ANALYZER_ARTIFACTORY_URL, "https://artifactory.techno.ingenico.com/artifactory");
        final ArtifactorySearch artifactorySearch = new ArtifactorySearch(settings);
        // When
        try {
            artifactorySearch.search(dependency);
            fail("No Match found, should throw an exception!");
        } catch (FileNotFoundException e) {
            // Then
            assertEquals("Artifact Dependency{ fileName='null', actualFilePath='null', filePath='null', packagePath='null'} not found in Artifactory", e.getMessage());
        }
    }

    @Test
    public void testWithRealInstanceWithUserToken() throws IOException {
        // Given
        Dependency dependency = new Dependency();
        dependency.setSha1sum("0695b63d702f505b9b916e02272e3b6381bade7f");
        dependency.setMd5sum("cde1963375c651f769d40c8023ab5876");

        final Settings settings = new Settings();
        settings.setString(Settings.KEYS.ANALYZER_ARTIFACTORY_URL, "https://artifactory.techno.ingenico.com/artifactory");
        settings.setString(Settings.KEYS.ANALYZER_ARTIFACTORY_API_USERNAME, "yourUserName");
        settings.setString(Settings.KEYS.ANALYZER_ARTIFACTORY_API_TOKEN, "yourSecretApiToken");
        final ArtifactorySearch artifactorySearch = new ArtifactorySearch(settings);
        // When
        final List<MavenArtifact> mavenArtifacts = artifactorySearch.search(dependency);

        // Then
        assertEquals(1, mavenArtifacts.size());
        final MavenArtifact artifact = mavenArtifacts.get(0);
        assertEquals("com.google.code.gson", artifact.getGroupId());
        assertEquals("gson", artifact.getArtifactId());
        assertEquals("2.4", artifact.getVersion());
        assertEquals("https://artifactory.techno.ingenico.com/artifactory/gradle-libs-cache/com/google/code/gson/gson/2.4/gson-2.4.jar", artifact.getArtifactUrl());
        assertEquals("https://artifactory.techno.ingenico.com/artifactory/gradle-libs-cache/com/google/code/gson/gson/2.4/gson-2.4.pom", artifact.getPomUrl());
    }


}
