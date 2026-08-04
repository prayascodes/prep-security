package com.prepplatform.security.jwt.spi;

import java.time.Clock;

public interface ClockProvider {

  Clock clock();
}
