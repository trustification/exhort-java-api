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
package com.redhat.exhort.cli;

public class AppUtils {
  public static void exitWithError() {
    System.exit(1);
  }

  public static void printLine(String message) {
    System.out.println(message);
  }

  public static void printLine() {
    System.out.println();
  }

  public static void printError(String message) {
    System.err.println(message);
    System.err.println();
  }

  public static void printException(Exception e) {
    printError("Error: " + e.getMessage());
  }
}
