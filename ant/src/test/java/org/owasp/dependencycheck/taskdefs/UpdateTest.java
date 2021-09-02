package org.owasp.dependencycheck.taskdefs;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.utils.Settings;

public class UpdateTest extends BaseTest {

  @Test
  public void testPopulateSettingsShouldSetDefaultValueToCveUrlModified() throws Exception {
    // Given
    System.clearProperty(Settings.KEYS.CVE_MODIFIED_JSON);
    System.clearProperty(Settings.KEYS.CVE_BASE_JSON);

    final Update update = new Update();
    update.setCveUrlModified(null);
    update.setCveUrlBase("https://my-custom-mirror-of-nvd/feeds/json/cve/1.1/nvdcve-1.1-%d.json.gz");

    // When
    update.populateSettings();

    // Then
    String output = update.getSettings().getString(Settings.KEYS.CVE_MODIFIED_JSON);
    String expectedOutput = "https://my-custom-mirror-of-nvd/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz";
    assertThat("cveUrlModified must be set to a default of the same model", output, is(expectedOutput));
  }

  @Test
  public void testPopulateSettingsShouldSetDefaultValueToCveUrlModifiedWhenCveUrlModifiedIsEmpty() throws Exception {
    // Given
    System.clearProperty(Settings.KEYS.CVE_MODIFIED_JSON);
    System.clearProperty(Settings.KEYS.CVE_BASE_JSON);

    final Update update = new Update();
    update.setCveUrlModified("");
    update.setCveUrlBase("https://my-custom-mirror-of-nvd/feeds/json/cve/1.1/nvdcve-1.1-%d.json.gz");

    // When
    update.populateSettings();

    // Then
    String output = update.getSettings().getString(Settings.KEYS.CVE_MODIFIED_JSON);
    String expectedOutput = "https://my-custom-mirror-of-nvd/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz";
    assertThat("cveUrlModified must be set to a default of the same model when arg is empty", output,
        is(expectedOutput));
  }

  @Test
  public void testPopulateSettingsShouldNotSetDefaultValueToCveUrlModifiedWhenValueIsExplicitelySet() throws Exception {
    // Given
    System.clearProperty(Settings.KEYS.CVE_MODIFIED_JSON);
    System.clearProperty(Settings.KEYS.CVE_BASE_JSON);

    final Update update = new Update();
    update.setCveUrlModified("https://another-custom-mirror-of-nvd/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz");
    update.setCveUrlBase("https://my-custom-mirror-of-nvd/feeds/json/cve/1.1/some-unusual-file-name-%d.json.gz");

    // When
    update.populateSettings();

    // Then
    String output = update.getSettings().getString(Settings.KEYS.CVE_MODIFIED_JSON);
    String expectedOutput = "https://another-custom-mirror-of-nvd/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz";
    assertThat("cveUrlModified must be set to the specified value", output, is(expectedOutput));
  }

  @Test
  public void testPopulateSettingsShouldNotSetDefaultValueToCveUrlModifiedWhenUnknownValueIsSet() throws Exception {
    // Given
    System.clearProperty(Settings.KEYS.CVE_MODIFIED_JSON);
    System.clearProperty(Settings.KEYS.CVE_BASE_JSON);

    final Update update = new Update();
    update.setCveUrlModified(null);
    update.setCveUrlBase("https://my-custom-mirror-of-nvd/feeds/json/cve/1.1/some-unusual-file-name-%d.json.gz");

    // When
    update.populateSettings();

    // Then
    String output = update.getSettings().getString(Settings.KEYS.CVE_MODIFIED_JSON);
    String expectedOutput = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz";
    assertThat("cveUrlModified must not be set when name is not the same as from the nvd datasource", output,
        is(expectedOutput));
  }

}
