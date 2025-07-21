/*
 * Copyright © 2025 Red Hat, Inc.
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
package com.redhat.exhort.cli;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.mockStatic;

import com.redhat.exhort.ExhortTest;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class AppTest extends ExhortTest {

  @Nested
  class HelpFunctionalityTests {

    @Test
    void main_with_no_args_should_print_help() {
      try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
        App.main(new String[0]);

        mockedAppUtils.verify(() -> AppUtils.printLine(contains("Exhort Java API CLI")));
      }
    }

    @ParameterizedTest
    @ValueSource(strings = {"--help", "-h"})
    void main_with_help_flag_should_print_help(String helpFlag) {
      try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
        App.main(new String[] {helpFlag});

        mockedAppUtils.verify(() -> AppUtils.printLine(contains("Exhort Java API CLI")));
        mockedAppUtils.verify(() -> AppUtils.printLine(contains("USAGE:")));
        mockedAppUtils.verify(
            () ->
                AppUtils.printLine(
                    contains("java -jar exhort-java-api.jar <COMMAND> <FILE_PATH> [OPTIONS]")));
      }
    }

    @Test
    void main_with_help_flag_after_other_args_should_print_help() {
      try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
        App.main(new String[] {"stack", "--help"});

        mockedAppUtils.verify(() -> AppUtils.printLine(contains("Exhort Java API CLI")));
      }
    }

    @Test
    void help_should_contain_usage_section() {
      try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
        App.main(new String[] {"--help"});

        mockedAppUtils.verify(() -> AppUtils.printLine(contains("USAGE:")));
        mockedAppUtils.verify(
            () ->
                AppUtils.printLine(
                    contains("java -jar exhort-java-api.jar <COMMAND> <FILE_PATH> [OPTIONS]")));
      }
    }

    @Test
    void help_should_contain_commands_section() {
      try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
        App.main(new String[] {"--help"});

        mockedAppUtils.verify(() -> AppUtils.printLine(contains("COMMANDS:")));
        mockedAppUtils.verify(
            () -> AppUtils.printLine(contains("stack <file_path> [--summary|--html]")));
        mockedAppUtils.verify(
            () -> AppUtils.printLine(contains("component <file_path> [--summary]")));
      }
    }

    @Test
    void help_should_contain_stack_command_description() {
      try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
        App.main(new String[] {"--help"});

        mockedAppUtils.verify(
            () ->
                AppUtils.printLine(
                    contains("Perform stack analysis on the specified manifest file")));
        mockedAppUtils.verify(
            () -> AppUtils.printLine(contains("--summary    Output summary in JSON format")));
        mockedAppUtils.verify(
            () -> AppUtils.printLine(contains("--html       Output full report in HTML format")));
        mockedAppUtils.verify(
            () -> AppUtils.printLine(contains("(default)    Output full report in JSON format")));
      }
    }

    @Test
    void help_should_contain_component_command_description() {
      try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
        App.main(new String[] {"--help"});

        mockedAppUtils.verify(
            () ->
                AppUtils.printLine(
                    contains("Perform component analysis on the specified manifest file")));
        mockedAppUtils.verify(
            () -> AppUtils.printLine(contains("--summary    Output summary in JSON format")));
        mockedAppUtils.verify(
            () -> AppUtils.printLine(contains("(default)    Output full report in JSON format")));
      }
    }

    @Test
    void help_should_contain_options_section() {
      try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
        App.main(new String[] {"--help"});

        mockedAppUtils.verify(() -> AppUtils.printLine(contains("OPTIONS:")));
        mockedAppUtils.verify(
            () -> AppUtils.printLine(contains("-h, --help     Show this help message")));
      }
    }

    @Test
    void help_should_contain_examples_section() {
      try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
        App.main(new String[] {"--help"});

        mockedAppUtils.verify(() -> AppUtils.printLine(contains("EXAMPLES:")));
        mockedAppUtils.verify(
            () ->
                AppUtils.printLine(
                    contains("java -jar exhort-java-api.jar stack /path/to/pom.xml")));
        mockedAppUtils.verify(
            () ->
                AppUtils.printLine(
                    contains(
                        "java -jar exhort-java-api.jar stack /path/to/package.json --summary")));
        mockedAppUtils.verify(
            () ->
                AppUtils.printLine(
                    contains("java -jar exhort-java-api.jar stack /path/to/build.gradle --html")));
        mockedAppUtils.verify(
            () ->
                AppUtils.printLine(
                    contains("java -jar exhort-java-api.jar component /path/to/requirements.txt")));
      }
    }
  }

  @Nested
  class ErrorHandlingTests {

    @Test
    void main_with_missing_arguments_should_exit_with_error() {
      try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
        App.main(new String[] {"stack"});

        // The app should print exception and exit - matches actual App.java behavior
        mockedAppUtils.verify(() -> AppUtils.printException(any(Exception.class)));
        mockedAppUtils.verify(() -> AppUtils.exitWithError());
      }
    }

    @Test
    void main_with_invalid_command_should_exit_with_error() {
      try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
        App.main(new String[] {"invalidcommand", "somefile.txt"});

        // The app should print exception and exit - matches actual App.java behavior
        mockedAppUtils.verify(() -> AppUtils.printException(any(Exception.class)));
        mockedAppUtils.verify(() -> AppUtils.exitWithError());
      }
    }
  }

  @Nested
  class HelpFileHandlingTests {

    @Test
    void help_loads_from_external_file() {
      try (MockedStatic<AppUtils> mockedAppUtils = mockStatic(AppUtils.class)) {
        App.main(new String[] {"--help"});

        // Verify that help content is printed (loaded from cli_help.txt)
        mockedAppUtils.verify(() -> AppUtils.printLine(contains("Exhort Java API CLI")));
        mockedAppUtils.verify(() -> AppUtils.printLine(contains("USAGE:")));
        mockedAppUtils.verify(() -> AppUtils.printLine(contains("COMMANDS:")));
        mockedAppUtils.verify(() -> AppUtils.printLine(contains("EXAMPLES:")));
      }
    }
  }
}
