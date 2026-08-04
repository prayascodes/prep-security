package com.prepplatform.security.jwt;

import com.prepplatform.security.AuthenticatedPrincipal;

public interface JwtSigner {

  String sign(AuthenticatedPrincipal principal, JwtTokenType type);
}
