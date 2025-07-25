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
package com.redhat.exhort.utils;

import java.util.Optional;

public final class Environment {

  private Environment() {}

  public static String get(String name, String defaultValue) {
    return Optional.ofNullable(System.getProperty(name))
        .or(() -> Optional.ofNullable(System.getenv(name)))
        .orElse(defaultValue);
  }

  public static String get(String name) {
    return get(name, null);
  }

  public static boolean getBoolean(String key, boolean defaultValue) {
    var val = get(key);
    if (val != null) {
      return Boolean.parseBoolean(val.trim().toLowerCase());
    }
    return defaultValue;
  }
}
