package com.prepplatform.security.jwt;

public enum JwtTokenType {
  ACCESS("access"),
  REFRESH("refresh");

  public final String name;

  JwtTokenType(String name) {
    this.name = name;
  }
}
