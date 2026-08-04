package com.prepplatform.security;

import java.util.Map;
import java.util.Set;
import org.jspecify.annotations.Nullable;

public record AuthenticatedPrincipal(String id, Set<String> authorities,
                                     Map<String, Object> attributes) {

  public AuthenticatedPrincipal {
    if (authorities.isEmpty()) {
      throw new IllegalArgumentException("AuthenticatedPrincipal.authorities cannot be empty.");
    }

    authorities = Set.copyOf(authorities);
    attributes = Map.copyOf(attributes);
  }

  public void addAttribute(String key, Object value) {
    attributes.put(key, value);
  }

  public <T> T requiredAttribute(String key, Class<T> type) {
    var val = getAttribute(key, type);

    if (val == null) {
      throw new IllegalStateException("Required attribute '" + key + "' is not present.");
    }

    return val;
  }

  public <T> @Nullable T getAttribute(String key, Class<T> type) {
    var val = attributes.get(key);
    return val == null ? null : type.cast(val);
  }
}
