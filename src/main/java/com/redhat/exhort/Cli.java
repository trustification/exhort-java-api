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
package com.redhat.exhort;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.redhat.exhort.api.v4.AnalysisReport;
import com.redhat.exhort.api.v4.ProviderReport;
import com.redhat.exhort.api.v4.Source;
import com.redhat.exhort.impl.ExhortApi;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

public class Cli {

  private static final ObjectMapper MAPPER = new ObjectMapper();

  static {
    MAPPER.setSerializationInclusion(JsonInclude.Include.NON_NULL);
  }

  private enum Command {
    STACK,
    COMPONENT
  }

  private enum OutputFormat {
    JSON,
    SUMMARY,
    HTML
  }

  public static void main(String[] args) {
    if (args.length == 0 || isHelpRequested(args)) {
      printHelp();
      return;
    }

    try {
      CliArgs cliArgs = parseArgs(args);
      String result = executeCommand(cliArgs).get();
      System.out.println(result);
    } catch (IllegalArgumentException e) {
      System.err.println("Error: " + e.getMessage());
      System.err.println();
      printHelp();
      System.exit(1);
    } catch (IOException | InterruptedException | ExecutionException e) {
      System.err.println("Unexpected error: " + e.getMessage());
      System.exit(1);
    }
  }

  private static boolean isHelpRequested(String[] args) {
    for (String arg : args) {
      if ("--help".equals(arg) || "-h".equals(arg)) {
        return true;
      }
    }
    return false;
  }

  private static CliArgs parseArgs(String[] args) {
    if (args.length < 2) {
      throw new IllegalArgumentException("Missing required arguments");
    }

    String commandStr = args[0].toLowerCase();
    Command command;

    switch (commandStr) {
      case "stack":
        command = Command.STACK;
        break;
      case "component":
        command = Command.COMPONENT;
        break;
      default:
        throw new IllegalArgumentException(
            "Unknown command: " + commandStr + ". Use 'stack' or 'component'");
    }

    String filePath = args[1];
    Path path = Paths.get(filePath);

    if (!Files.exists(path)) {
      throw new IllegalArgumentException("File does not exist: " + filePath);
    }

    if (!Files.isRegularFile(path)) {
      throw new IllegalArgumentException("Path is not a file: " + filePath);
    }

    OutputFormat outputFormat = OutputFormat.JSON; // default

    // Parse additional options for stack command
    if (args.length > 2) {
      for (int i = 2; i < args.length; i++) {
        switch (args[i]) {
          case "--summary":
            outputFormat = OutputFormat.SUMMARY;
            break;
          case "--html":
            if (command != Command.STACK) {
              throw new IllegalArgumentException("HTML format is only supported for stack command");
            }
            outputFormat = OutputFormat.HTML;
            break;
          default:
            throw new IllegalArgumentException("Unknown option for stack command: " + args[i]);
        }
      }
    } else if (command == Command.COMPONENT && args.length > 2) {
      throw new IllegalArgumentException("Component command does not accept additional options");
    }

    return new CliArgs(command, path, outputFormat);
  }

  private static CompletableFuture<String> executeCommand(CliArgs args) throws IOException {
    switch (args.command) {
      case STACK:
        return executeStackAnalysis(args.filePath.toAbsolutePath().toString(), args.outputFormat);
      case COMPONENT:
        return executeComponentAnalysis(
            args.filePath.toAbsolutePath().toString(), args.outputFormat);
      default:
        throw new AssertionError();
    }
  }

  private static CompletableFuture<String> executeStackAnalysis(
      String filePath, OutputFormat outputFormat) throws IOException {
    Api api = new ExhortApi();
    switch (outputFormat) {
      case JSON:
        return api.stackAnalysis(filePath).thenApply(Cli::toJsonString);
      case HTML:
        return api.stackAnalysisHtml(filePath).thenApply(bytes -> new String(bytes));
      case SUMMARY:
        return api.stackAnalysis(filePath)
            .thenApply(Cli::extractSummary)
            .thenApply(Cli::toJsonString);
      default:
        throw new AssertionError();
    }
  }

  private static CompletableFuture<String> executeComponentAnalysis(
      String filePath, OutputFormat outputFormat) throws IOException {
    Api api = new ExhortApi();
    CompletableFuture<AnalysisReport> analysis = api.componentAnalysis(filePath);
    if (outputFormat.equals(OutputFormat.SUMMARY)) {
      analysis = analysis.thenApply(Cli::extractSummary);
    }
    return analysis.thenApply(Cli::toJsonString);
  }

  private static String toJsonString(Object obj) {
    try {
      return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(obj);
    } catch (JsonProcessingException e) {
      throw new RuntimeException("Failed to serialize to JSON", e);
    }
  }

  private static AnalysisReport extractSummary(AnalysisReport report) {
    AnalysisReport summary = new AnalysisReport();
    summary.setScanned(report.getScanned());
    if (report.getProviders() == null) {
      return summary;
    }
    report
        .getProviders()
        .entrySet()
        .forEach(
            entry -> {
              var provider = new ProviderReport();
              provider.setStatus(entry.getValue().getStatus());
              if (entry.getValue().getSources() != null) {
                entry
                    .getValue()
                    .getSources()
                    .entrySet()
                    .forEach(
                        sourceEntry -> {
                          var source = new Source();
                          source.setSummary(sourceEntry.getValue().getSummary());
                          provider.putSourcesItem(sourceEntry.getKey(), source);
                        });
              }
              summary.putProvidersItem(entry.getKey(), provider);
            });
    return summary;
  }

  private static void printHelp() {
    System.out.println("Exhort Java API CLI");
    System.out.println();
    System.out.println("USAGE:");
    System.out.println("  java -jar exhort-java-api.jar <COMMAND> <FILE_PATH> [OPTIONS]");
    System.out.println();
    System.out.println("COMMANDS:");
    System.out.println("  stack <file_path> [--summary|--html]");
    System.out.println("    Perform stack analysis on the specified manifest file");
    System.out.println("    Options:");
    System.out.println("      --summary    Output summary in JSON format");
    System.out.println("      --html       Output full report in HTML format");
    System.out.println("      (default)    Output full report in JSON format");
    System.out.println();
    System.out.println("  component <file_path> [--summary]");
    System.out.println("    Perform component analysis on the specified manifest file");
    System.out.println("    Options:");
    System.out.println("      --summary    Output summary in JSON format");
    System.out.println("      (default)    Output full report in JSON format");
    System.out.println();
    System.out.println("OPTIONS:");
    System.out.println("  -h, --help     Show this help message");
    System.out.println();
    System.out.println("EXAMPLES:");
    System.out.println("  java -jar exhort-java-api.jar stack /path/to/pom.xml");
    System.out.println("  java -jar exhort-java-api.jar stack /path/to/package.json --summary");
    System.out.println("  java -jar exhort-java-api.jar stack /path/to/build.gradle --html");
    System.out.println("  java -jar exhort-java-api.jar component /path/to/requirements.txt");
  }

  private static class CliArgs {
    final Command command;
    final Path filePath;
    final OutputFormat outputFormat;

    CliArgs(Command command, Path filePath, OutputFormat outputFormat) {
      this.command = command;
      this.filePath = filePath;
      this.outputFormat = outputFormat;
    }
  }
}
