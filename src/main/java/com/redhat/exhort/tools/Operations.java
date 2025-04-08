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
package com.redhat.exhort.tools;

import static java.lang.String.join;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/** Utility class used for executing process on the operating system. * */
public final class Operations {
  private Operations() {
    // constructor not required for a utility class
  }

  /**
   * Function for looking up custom executable path based on the default one provides as an
   * argument. I.e. if defaultExecutable=mvn, this function will look for a custom mvn path set as
   * an environment variable or a java property with the name EXHORT_MVN_PATH. If not found, the
   * original mvn passed as defaultExecutable will be returned. Note, environment variables takes
   * precedence on java properties.
   *
   * @param defaultExecutable default executable (uppercase spaces and dashes will be replaced with
   *     underscores).
   * @return the custom path from the relevant environment variable or the original argument.
   */
  public static String getCustomPathOrElse(String defaultExecutable) {
    var target = defaultExecutable.toUpperCase().replaceAll(" ", "_").replaceAll("-", "_");
    var executableKey = String.format("EXHORT_%s_PATH", target);
    return Objects.requireNonNullElseGet(
        System.getenv(executableKey),
        () -> Objects.requireNonNullElse(System.getProperty(executableKey), defaultExecutable));
  }

  /**
   * Function for building a command from the command parts list and execute it as a process on the
   * operating system. Will throw a RuntimeException if the command build or execution failed.
   *
   * @param cmdList list of command parts
   */
  public static void runProcess(final String... cmdList) {
    runProcess(cmdList, null);
  }

  public static void runProcess(final String[] cmdList, final Map<String, String> envMap) {
    var processBuilder = new ProcessBuilder();
    processBuilder.command(cmdList);
    if (envMap != null) {
      processBuilder.environment().putAll(envMap);
    }
    // create a process builder or throw a runtime exception
    Process process = null;
    try {
      process = processBuilder.start();
    } catch (final IOException e) {
      throw new RuntimeException(
          String.format(
              "failed to build process for '%s' got %s", join(" ", cmdList), e.getMessage()));
    }

    // execute the command or throw runtime exception if failed
    int exitCode = 0;
    try {
      exitCode = process.waitFor();

    } catch (final InterruptedException e) {
      throw new RuntimeException(
          String.format(
              "built process for '%s' interrupted, got %s", join(" ", cmdList), e.getMessage()));
    }
    // verify the command was executed successfully or throw a runtime exception
    if (exitCode != 0) {
      String errMsg = "";
      try (var reader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
        errMsg = reader.lines().collect(Collectors.joining(System.lineSeparator()));
      } catch (IOException e) {
        throw new RuntimeException(
            String.format(
                "unable to process error output for '%s', got %s",
                join(" ", cmdList), e.getMessage()));
      }

      if (errMsg.isEmpty()) {
        try (var reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
          errMsg = reader.lines().collect(Collectors.joining(System.lineSeparator()));
        } catch (IOException e) {
          throw new RuntimeException(
              String.format(
                  "unable to process output for '%s', got %s", join(" ", cmdList), e.getMessage()));
        }
      }
      if (errMsg.isEmpty()) {
        throw new RuntimeException(
            String.format("failed to execute '%s', exit-code %d", join(" ", cmdList), exitCode));
      } else {
        throw new RuntimeException(
            String.format(
                "failed to execute '%s', exit-code %d, message:%s%s%s",
                join(" ", cmdList),
                exitCode,
                System.lineSeparator(),
                errMsg,
                System.lineSeparator()));
      }
    }
  }

  public static String runProcessGetOutput(Path dir, final String... cmdList) {
    return runProcessGetOutput(dir, cmdList, null);
  }

  public static String runProcessGetOutput(Path dir, final String[] cmdList, String[] envList) {
    try {
      Process process;
      if (dir == null) {
        if (envList != null) {
          process = Runtime.getRuntime().exec(cmdList, envList);
        } else {
          process = Runtime.getRuntime().exec(cmdList, null);
        }
      } else {
        if (envList != null) {
          process = Runtime.getRuntime().exec(cmdList, envList, dir.toFile());
        } else {
          process = Runtime.getRuntime().exec(cmdList, null, dir.toFile());
        }
      }

      String stdout = new String(process.getInputStream().readAllBytes());
      String stderr = new String(process.getErrorStream().readAllBytes());

      // TODO: This should throw an exception if the process fails
      if (!stderr.isBlank()) {
        return stderr.trim();
      }
      return stdout.trim();
    } catch (IOException e) {
      throw new RuntimeException(
          String.format("Failed to execute command '%s' ", join(" ", cmdList)), e);
    }
  }

  public static ProcessExecOutput runProcessGetFullOutput(
      Path dir, final String[] cmdList, String[] envList) {
    try {
      Process process;
      if (dir == null) {
        if (envList != null) {
          process = Runtime.getRuntime().exec(cmdList, envList);
        } else {
          process = Runtime.getRuntime().exec(cmdList);
        }
      } else {
        if (envList != null) {
          process = Runtime.getRuntime().exec(cmdList, envList, dir.toFile());
        } else {
          process = Runtime.getRuntime().exec(cmdList, null, dir.toFile());
        }
      }

      BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
      StringBuilder output = new StringBuilder();
      String line;
      while ((line = reader.readLine()) != null) {
        output.append(line);
        if (!line.endsWith(System.lineSeparator())) {
          output.append("\n");
        }
      }

      reader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
      StringBuilder error = new StringBuilder();
      while ((line = reader.readLine()) != null) {
        error.append(line);
        if (!line.endsWith(System.lineSeparator())) {
          error.append("\n");
        }
      }

      process.waitFor(30L, TimeUnit.SECONDS);

      return new ProcessExecOutput(output.toString(), error.toString(), process.exitValue());
    } catch (IOException | InterruptedException e) {
      throw new RuntimeException(
          String.format("Failed to execute command '%s' ", join(" ", cmdList)), e);
    }
  }

  public static class ProcessExecOutput {
    private String output;
    private String error;
    private int exitCode;

    public ProcessExecOutput(String output, String error, int exitCode) {
      this.output = output;
      this.error = error;
      this.exitCode = exitCode;
    }

    public String getOutput() {
      return output;
    }

    public String getError() {
      return error;
    }

    public int getExitCode() {
      return exitCode;
    }
  }
}
