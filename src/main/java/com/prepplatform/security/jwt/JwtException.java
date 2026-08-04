package com.prepplatform.security.jwt;

public class JwtException extends RuntimeException {

  public JwtException(String message) {
    super(message);
  }

  public JwtException(String message, Throwable cause) {
    super(message, cause);
  }

  public void setCause(Throwable cause) {
    super.initCause(cause);
  }
}
