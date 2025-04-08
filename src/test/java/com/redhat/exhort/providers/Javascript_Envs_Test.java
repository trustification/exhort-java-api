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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.File;
import java.util.Collections;
import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.ClearEnvironmentVariable;
import org.junitpioneer.jupiter.ClearSystemProperty;
import org.junitpioneer.jupiter.SetEnvironmentVariable;
import org.junitpioneer.jupiter.SetSystemProperty;

public class Javascript_Envs_Test {
  @Test
  @SetSystemProperty(key = "NODE_HOME", value = "test-node-home")
  @SetEnvironmentVariable(key = "PATH", value = "test-path")
  void test_javascript_get_envs() {
    var envs = new JavaScriptNpmProvider(null).getNpmExecEnv();
    assertEquals(
        Collections.singletonMap("PATH", "test-path" + File.pathSeparator + "test-node-home"),
        envs);
  }

  @Test
  @SetSystemProperty(key = "NODE_HOME", value = "test-node-home")
  @ClearEnvironmentVariable(key = "PATH")
  void test_javascript_get_envs_no_path() {
    var envs = new JavaScriptNpmProvider(null).getNpmExecEnv();
    assertEquals(Collections.singletonMap("PATH", "test-node-home"), envs);
  }

  @Test
  @SetSystemProperty(key = "NODE_HOME", value = "")
  @SetEnvironmentVariable(key = "PATH", value = "test-path")
  void test_javascript_get_envs_empty_java_home() {
    var envs = new JavaScriptNpmProvider(null).getNpmExecEnv();
    assertNull(envs);
  }

  @Test
  @ClearSystemProperty(key = "NODE_HOME")
  @SetEnvironmentVariable(key = "PATH", value = "test-path")
  void test_javascript_get_envs_no_java_home() {
    var envs = new JavaScriptNpmProvider(null).getNpmExecEnv();
    assertNull(envs);
  }
}
