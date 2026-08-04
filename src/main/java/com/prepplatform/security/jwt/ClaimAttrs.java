package com.prepplatform.security.jwt;

public enum ClaimAttrs {
  AUTHORITIES("authorities"),
  ATTRS("attrs"),
  TOKEN_TYPE("token_type");

  public final String name;

  ClaimAttrs(String name) {
    this.name = name;
  }
}
