/*
 * Copyright © 2023 Red Hat, Inc.
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
 */
package com.redhat.exhort.providers;

import static com.redhat.exhort.Provider.PROP_MATCH_MANIFEST_VERSIONS;
import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.*;

import com.redhat.exhort.Api;
import com.redhat.exhort.ExhortTest;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

@ExtendWith(HelperExtension.class)
class Golang_Modules_Provider_Test extends ExhortTest {
  // test folder are located at src/test/resources/tst_manifests/npm
  // each folder should contain:
  // - package.json: the target manifest for testing
  // - expected_sbom.json: the SBOM expected to be provided
  static Stream<String> testFolders() {
    return Stream.of(
        "go_mod_light_no_ignore",
        "go_mod_no_ignore",
        "go_mod_with_ignore",
        "go_mod_with_all_ignore",
        "go_mod_with_one_ignored_prefix_go",
        "go_mod_no_path");
  }

  @ParameterizedTest
  @MethodSource("testFolders")
  void test_the_provideStack(String testFolder) throws IOException, InterruptedException {
    // create temp file hosting our sut package.json
    var tmpGoModulesDir = Files.createTempDirectory("exhort_test_");
    var tmpGolangFile = Files.createFile(tmpGoModulesDir.resolve("go.mod"));
    try (var is =
        getResourceAsStreamDecision(
            this.getClass(), String.format("tst_manifests/golang/%s/go.mod", testFolder))) {
      Files.write(tmpGolangFile, is.readAllBytes());
    }
    // load expected SBOM
    String expectedSbom;
    try (var is =
        getResourceAsStreamDecision(
            this.getClass(),
            String.format(
                "tst_manifests/golang/%s/expected_sbom_stack_analysis.json", testFolder))) {
      expectedSbom = new String(is.readAllBytes());
    }
    // when providing stack content for our pom
    var content = new GoModulesProvider(tmpGolangFile).provideStack();
    // cleanup
    Files.deleteIfExists(tmpGolangFile);
    // verify expected SBOM is returned
    assertThat(content.type).isEqualTo(Api.CYCLONEDX_MEDIA_TYPE);
    assertThat(dropIgnored(new String(content.buffer))).isEqualTo(dropIgnored(expectedSbom));
  }

  @ParameterizedTest
  @MethodSource("testFolders")
  void test_the_provideComponent(String testFolder) throws IOException, InterruptedException {
    // create temp file hosting our sut package.json
    var tmpGoModulesDir = Files.createTempDirectory("exhort_test_");
    var tmpGolangFile = Files.createFile(tmpGoModulesDir.resolve("go.mod"));
    try (var is =
        getResourceAsStreamDecision(
            this.getClass(), String.format("tst_manifests/golang/%s/go.mod", testFolder))) {
      Files.write(tmpGolangFile, is.readAllBytes());
    }
    // load expected SBOM
    String expectedSbom = "";
    try (var is =
        getResourceAsStreamDecision(
            this.getClass(),
            String.format(
                "tst_manifests/golang/%s/expected_sbom_component_analysis.json", testFolder))) {
      expectedSbom = new String(is.readAllBytes());
    }
    // when providing component content for our pom
    var content = new GoModulesProvider(tmpGolangFile).provideComponent();
    // cleanup
    Files.deleteIfExists(tmpGolangFile);
    // verify expected SBOM is returned
    assertThat(content.type).isEqualTo(Api.CYCLONEDX_MEDIA_TYPE);
    assertThat(dropIgnored(new String(content.buffer))).isEqualTo(dropIgnored(expectedSbom));
  }

  @Test
  void Test_The_ProvideComponent_Path_Should_Throw_Exception() {

    GoModulesProvider goModulesProvider = new GoModulesProvider(Path.of("."));
    assertThatIllegalArgumentException()
        .isThrownBy(
            () -> {
              goModulesProvider.provideComponent();
            });
  }

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  void Test_Golang_Modules_with_Match_Manifest_Version(boolean MatchManifestVersionsEnabled) {
    String goModPath = getFileFromResource("go.mod", "msc/golang/go.mod");
    GoModulesProvider goModulesProvider = new GoModulesProvider(Path.of(goModPath));

    if (MatchManifestVersionsEnabled) {
      System.setProperty(PROP_MATCH_MANIFEST_VERSIONS, "true");
      RuntimeException runtimeException =
          assertThrows(
              RuntimeException.class,
              () -> goModulesProvider.getDependenciesSbom(Path.of(goModPath), true),
              "Expected getDependenciesSbom/2 to throw RuntimeException, due to version mismatch,"
                  + " but it didn't.");
      assertTrue(
          runtimeException
              .getMessage()
              .contains(
                  "Can't continue with analysis - versions mismatch for dependency"
                      + " name=github.com/google/uuid, manifest version=v1.1.0, installed"
                      + " Version=v1.1.1"));
      System.clearProperty(PROP_MATCH_MANIFEST_VERSIONS);
    } else {
      String sbomString =
          assertDoesNotThrow(
              () ->
                  goModulesProvider
                      .getDependenciesSbom(Path.of(goModPath), false)
                      .getAsJsonString());
      String actualSbomWithTSStripped = dropIgnoredKeepFormat(sbomString);
      assertEquals(
          getStringFromFile("msc/golang/expected_sbom_ca.json").trim(), actualSbomWithTSStripped);

      System.out.println(sbomString);
    }
  }

  @Test
  void Test_Golang_MvS_Logic_Enabled() throws IOException {
    System.setProperty(GoModulesProvider.PROP_EXHORT_GO_MVS_LOGIC_ENABLED, "true");
    String goModPath = getFileFromResource("go.mod", "msc/golang/mvs_logic/go.mod");
    GoModulesProvider goModulesProvider = new GoModulesProvider(Path.of(goModPath));
    String resultSbom =
        dropIgnoredKeepFormat(
            goModulesProvider.getDependenciesSbom(Path.of(goModPath), true).getAsJsonString());
    String expectedSbom =
        getStringFromFile("msc/golang/mvs_logic/expected_sbom_stack_analysis.json").trim();

    assertEquals(expectedSbom, resultSbom);

    // check that only one version of package golang/go.opencensus.io is in sbom for
    // EXHORT_GO_MVS_LOGIC_ENABLED=true
    assertTrue(
        Arrays.stream(resultSbom.split(System.lineSeparator()))
                .filter(str -> str.contains("\"ref\" : \"pkg:golang/go.opencensus.io@"))
                .count()
            == 1);

    System.clearProperty(GoModulesProvider.PROP_EXHORT_GO_MVS_LOGIC_ENABLED);

    resultSbom =
        dropIgnoredKeepFormat(
            goModulesProvider.getDependenciesSbom(Path.of(goModPath), true).getAsJsonString());
    // check that there is more than one version of package golang/go.opencensus.io in sbom for
    // EXHORT_GO_MVS_LOGIC_ENABLED=false
    assertTrue(
        Arrays.stream(resultSbom.split(System.lineSeparator()))
                .filter(str -> str.contains("\"ref\" : \"pkg:golang/go.opencensus.io@"))
                .count()
            > 1);
  }

  private String dropIgnored(String s) {
    return s.replaceAll("\\s+", "").replaceAll("\"timestamp\":\"[a-zA-Z0-9\\-\\:]+\",", "");
  }

  private String dropIgnoredKeepFormat(String s) {
    return s.replaceAll("\"timestamp\" : \"[a-zA-Z0-9\\-\\:]+\",\n    ", "");
  }
}
