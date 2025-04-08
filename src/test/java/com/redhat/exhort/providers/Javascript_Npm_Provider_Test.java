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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.redhat.exhort.Api;
import com.redhat.exhort.ExhortTest;
import com.redhat.exhort.tools.Operations;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.*;

@ExtendWith(HelperExtension.class)
class Javascript_Npm_Provider_Test extends ExhortTest {
  // test folder are located at src/test/resources/tst_manifests/npm
  // each folder should contain:
  // - package.json: the target manifest for testing
  // - expected_sbom.json: the SBOM expected to be provided
  static Stream<String> testFolders() {
    return Stream.of("deps_with_ignore", "deps_with_no_ignore");
  }

  @ParameterizedTest
  @MethodSource("testFolders")
  void test_the_provideStack(String testFolder) throws IOException, InterruptedException {
    // create temp file hosting our sut package.json
    var tmpNpmFolder = Files.createTempDirectory("exhort_test_");
    var tmpNpmFile = Files.createFile(tmpNpmFolder.resolve("package.json"));
    var tmpLockFile = Files.createFile(tmpNpmFolder.resolve("package-lock.json"));
    try (var is =
        getResourceAsStreamDecision(
            this.getClass(), String.format("tst_manifests/npm/%s/package.json", testFolder))) {
      Files.write(tmpNpmFile, is.readAllBytes());
    }

    try (var is =
        getResourceAsStreamDecision(
            this.getClass(), String.format("tst_manifests/npm/%s/package-lock.json", testFolder))) {
      Files.write(tmpLockFile, is.readAllBytes());
    }
    // load expected SBOM
    String expectedSbom;
    try (var is =
        getResourceAsStreamDecision(
            this.getClass(),
            String.format("tst_manifests/npm/%s/expected_stack_sbom.json", testFolder))) {
      expectedSbom = new String(is.readAllBytes());
    }
    String npmListingStack;
    try (var is =
        getResourceAsStreamDecision(
            this.getClass(), String.format("tst_manifests/npm/%s/npm-ls-stack.json", testFolder))) {
      npmListingStack = new String(is.readAllBytes());
    }

    ArgumentMatcher<Path> matchPath = path -> path == null;
    try (MockedStatic<Operations> mockedOperations = mockStatic(Operations.class)) {
      mockedOperations
          .when(() -> Operations.runProcessGetOutput(argThat(matchPath), any(String[].class)))
          .thenReturn(npmListingStack);
      // when providing stack content for our pom
      var content = new JavaScriptNpmProvider(tmpNpmFile).provideStack();
      // cleanup
      Files.deleteIfExists(tmpNpmFile);
      Files.deleteIfExists(tmpLockFile);
      Files.deleteIfExists(tmpNpmFolder);
      // verify expected SBOM is returned
      assertThat(content.type).isEqualTo(Api.CYCLONEDX_MEDIA_TYPE);
      assertThat(dropIgnored(new String(content.buffer))).isEqualTo(dropIgnored(expectedSbom));
    }
  }

  @ParameterizedTest
  @MethodSource("testFolders")
  void test_the_provideComponent(String testFolder) throws IOException, InterruptedException {
    // load the pom target pom file
    var targetPom =
        String.format("src/test/resources/tst_manifests/npm/%s/package.json", testFolder);

    // load expected SBOM
    String expectedSbom = "";
    try (var is =
        getResourceAsStreamDecision(
            this.getClass(),
            String.format("tst_manifests/npm/%s/expected_component_sbom.json", testFolder))) {
      expectedSbom = new String(is.readAllBytes());
    }
    String npmListingComponent;
    try (var is =
        getResourceAsStreamDecision(
            this.getClass(),
            String.format("tst_manifests/npm/%s/npm-ls-component.json", testFolder))) {
      npmListingComponent = new String(is.readAllBytes());
    }

    try (MockedStatic<Operations> mockedOperations = mockStatic(Operations.class)) {
      mockedOperations
          .when(() -> Operations.runProcess(any(), any()))
          .thenAnswer(
              (invocationOnMock) -> {
                String[] commandParts = (String[]) invocationOnMock.getRawArguments()[0];
                int lastElementIsDir = commandParts.length - 1;
                String packageLockJson = commandParts[lastElementIsDir] + "/package-lock.json";

                return packageLockJson;
              });
      ArgumentMatcher<Path> matchPath = path -> path == null;

      mockedOperations
          .when(() -> Operations.runProcessGetOutput(argThat(matchPath), any(String[].class)))
          .thenReturn(npmListingComponent);
      // when providing component content for our pom
      var content = new JavaScriptNpmProvider(Path.of(targetPom)).provideComponent();
      // verify expected SBOM is returned
      assertThat(content.type).isEqualTo(Api.CYCLONEDX_MEDIA_TYPE);
      assertThat(dropIgnored(new String(content.buffer))).isEqualTo(dropIgnored(expectedSbom));
    }
  }

  @ParameterizedTest
  @MethodSource("testFolders")
  void test_the_provideComponent_with_Path(String testFolder) throws Exception {
    // load the pom target pom file

    // create temp file hosting our sut package.json
    var tmpNpmFolder = Files.createTempDirectory("exhort_test_");
    var tmpNpmFile = Files.createFile(tmpNpmFolder.resolve("package.json"));
    try (var is =
        getResourceAsStreamDecision(
            this.getClass(), String.format("tst_manifests/npm/%s/package.json", testFolder))) {
      Files.write(tmpNpmFile, is.readAllBytes());
    }
    String expectedSbom = "";
    try (var is =
        getResourceAsStreamDecision(
            this.getClass(),
            String.format("tst_manifests/npm/%s/expected_component_sbom.json", testFolder))) {
      expectedSbom = new String(is.readAllBytes());
    }
    String npmListingComponent;
    try (var is =
        getResourceAsStreamDecision(
            this.getClass(),
            String.format("tst_manifests/npm/%s/npm-ls-component.json", testFolder))) {
      npmListingComponent = new String(is.readAllBytes());
    }
    ArgumentMatcher<Path> matchPath = path -> path == null;
    try (MockedStatic<Operations> mockedOperations = mockStatic(Operations.class)) {
      mockedOperations
          .when(() -> Operations.runProcess(any(), any()))
          .thenAnswer(
              (invocationOnMock) -> {
                String[] commandParts = (String[]) invocationOnMock.getRawArguments()[0];
                int lastElementIsDir = commandParts.length - 1;
                String packageLockJson = commandParts[lastElementIsDir] + "/package-lock.json";
                Files.createFile(Path.of(packageLockJson));
                return packageLockJson;
              });
      mockedOperations
          .when(() -> Operations.runProcessGetOutput(argThat(matchPath), any(String[].class)))
          .thenReturn(npmListingComponent);
      // when providing component content for our pom
      var content = new JavaScriptNpmProvider(tmpNpmFile).provideComponent();
      // verify expected SBOM is returned
      assertThat(content.type).isEqualTo(Api.CYCLONEDX_MEDIA_TYPE);
      assertThat(dropIgnored(new String(content.buffer))).isEqualTo(dropIgnored(expectedSbom));
    }
  }

  private String dropIgnored(String s) {
    return s.replaceAll("\\s+", "").replaceAll("\"timestamp\":\"[a-zA-Z0-9\\-\\:]+\"", "");
  }
}
