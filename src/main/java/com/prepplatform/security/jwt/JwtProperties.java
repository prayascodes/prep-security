package com.prepplatform.security.jwt;

import java.time.Duration;
import java.util.List;

public record JwtProperties(String issuer, List<String> audiences, Duration accessTtl,
                            Duration refreshTtl) {

}

