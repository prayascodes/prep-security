package com.prepplatform.security.jwt;

public class JwtVerificationException extends JwtException {

  public JwtVerificationException(String message) {
    super(message);
  }

  public JwtVerificationException(String message, Throwable cause) {
    super(message, cause);
  }
}
