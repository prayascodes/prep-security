package com.prepplatform.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("AuthenticatedPrincipal")
class AuthenticatedPrincipalTest {

  @Nested
  @DisplayName("Constructor")
  class ConstructorTests {

    @Test
    @DisplayName("should create principal when authorities are provided")
    void shouldCreatePrincipal() {
      var authorities = Set.of("ROLE_USER");
      var attributes = Map.<String, Object>of("email", "user@example.com");

      var principal = new AuthenticatedPrincipal("123", authorities, attributes);

      assertThat(principal.id()).isEqualTo("123");
      assertThat(principal.authorities()).containsExactly("ROLE_USER");
      assertThat(principal.attributes()).containsEntry("email", "user@example.com");
    }

    @Test
    @DisplayName("should throw when authorities are empty")
    void shouldThrowWhenAuthoritiesAreEmpty() {
      assertThatThrownBy(() ->
          new AuthenticatedPrincipal("123", Set.of(), Map.of()))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessage("AuthenticatedPrincipal.authorities cannot be empty.");
    }

    @Test
    @DisplayName("should defensively copy authorities")
    void shouldDefensivelyCopyAuthorities() {
      var authorities = new HashSet<>(Set.of("ROLE_USER"));
      var principal = new AuthenticatedPrincipal("123", authorities, Map.of());
      authorities.add("ROLE_ADMIN");

      assertThat(principal.authorities()).containsExactly("ROLE_USER");
    }

    @Test
    @DisplayName("should defensively copy attributes")
    void shouldDefensivelyCopyAttributes() {
      var attributes = new HashMap<String, Object>();
      attributes.put("email", "user@example.com");
      var principal = new AuthenticatedPrincipal("123", Set.of("ROLE_USER"), attributes);
      attributes.put("email", "changed@example.com");
      attributes.put("name", "John");

      assertThat(principal.attributes()).containsEntry("email", "user@example.com")
          .doesNotContainKey("name");
    }

    @Test
    @DisplayName("should expose unmodifiable authorities")
    void shouldExposeUnmodifiableAuthorities() {
      var principal = new AuthenticatedPrincipal("123", Set.of("ROLE_USER"), Map.of());

      assertThatThrownBy(() -> principal.authorities().add("ROLE_ADMIN"))
          .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    @DisplayName("should expose unmodifiable attributes")
    void shouldExposeUnmodifiableAttributes() {
      var principal = new AuthenticatedPrincipal("123", Set.of("ROLE_USER"), Map.of());

      assertThatThrownBy(() -> principal.attributes().put("key", "value"))
          .isInstanceOf(UnsupportedOperationException.class);
    }
  }

  @Nested
  @DisplayName("getAttribute")
  class GetAttributeTests {

    @Test
    @DisplayName("should return attribute when present and of expected type")
    void shouldReturnAttribute() {
      var principal = new AuthenticatedPrincipal("123", Set.of("ROLE_USER"), Map.of("age", 25));
      Integer age = principal.getAttribute("age", Integer.class);

      assertThat(age).isEqualTo(25);
    }

    @Test
    @DisplayName("should return null when attribute is absent")
    void shouldReturnNullWhenAttributeMissing() {
      var principal = new AuthenticatedPrincipal("123", Set.of("ROLE_USER"), Map.of());
      String email = principal.getAttribute("email", String.class);

      assertThat(email).isNull();
    }

    @Test
    @DisplayName("should throw when attribute type does not match")
    void shouldThrowWhenAttributeTypeDoesNotMatch() {
      var principal = new AuthenticatedPrincipal("123", Set.of("ROLE_USER"), Map.of("age", 25));

      assertThatThrownBy(() -> principal.getAttribute("age", String.class))
          .isInstanceOf(ClassCastException.class);
    }
  }

  @Nested
  @DisplayName("requiredAttribute")
  class RequiredAttributeTests {

    @Test
    @DisplayName("should return required attribute when present")
    void shouldReturnRequiredAttribute() {
      var principal = new AuthenticatedPrincipal("123", Set.of("ROLE_USER"),
          Map.of("email", "user@example.com"));
      String email = principal.requiredAttribute("email", String.class);

      assertThat(email).isEqualTo("user@example.com");
    }

    @Test
    @DisplayName("should throw when required attribute is missing")
    void shouldThrowWhenRequiredAttributeMissing() {
      var principal = new AuthenticatedPrincipal("123", Set.of("ROLE_USER"), Map.of());

      assertThatThrownBy(() -> principal.requiredAttribute("email", String.class))
          .isInstanceOf(IllegalStateException.class)
          .hasMessage("Required attribute 'email' is not present.");
    }

    @Test
    @DisplayName("should throw when required attribute type does not match")
    void shouldThrowWhenRequiredAttributeTypeDoesNotMatch() {
      var principal = new AuthenticatedPrincipal("123", Set.of("ROLE_USER"), Map.of("age", 25));
      assertThatThrownBy(() -> principal.requiredAttribute("age", String.class))
          .isInstanceOf(ClassCastException.class);
    }
  }

  @Nested
  @DisplayName("addAttribute")
  class AddAttributeTests {

    @Test
    @DisplayName("should throw because attributes map is unmodifiable")
    void shouldThrowBecauseAttributesAreUnmodifiable() {
      var principal = new AuthenticatedPrincipal("123", Set.of("ROLE_USER"), new HashMap<>());

      assertThatThrownBy(() -> principal.addAttribute("email", "user@example.com"))
          .isInstanceOf(UnsupportedOperationException.class);
    }
  }
}
