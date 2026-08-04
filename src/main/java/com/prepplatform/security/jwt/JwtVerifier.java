package com.prepplatform.security.jwt;

import com.prepplatform.security.AuthenticatedPrincipal;

public interface JwtVerifier {

  AuthenticatedPrincipal verify(String token);
}
