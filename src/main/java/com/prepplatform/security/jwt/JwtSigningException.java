package com.prepplatform.security.jwt;

public class JwtSigningException extends JwtException {

  public JwtSigningException(String message) {
    super(message);
  }

  public JwtSigningException(String message, Throwable cause) {
    super(message, cause);
  }
}
