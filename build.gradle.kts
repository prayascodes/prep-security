plugins {
  id("com.pcodes.gradle.java-lib") version "1.0.0"
  id("com.pcodes.gradle.axion-release") version "1.0.0"
  id("com.pcodes.gradle.gpr-java-publish") version "1.0.0"
}

group = providers.gradleProperty("group").get()

version = scmVersion.version

gprJavaPublish {
  owner = providers.gradleProperty("owner").get()
  repository = "maven-releases"
}

dependencies {
  api("org.jspecify:jspecify:1.0.0")

  implementation("com.nimbusds:nimbus-jose-jwt:10.9.1")

  testImplementation(platform("org.junit:junit-bom:6.0.0"))
  testImplementation("org.junit.jupiter:junit-jupiter")
  testImplementation("org.assertj:assertj-core:3.27.7")
  testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
  useJUnitPlatform()
}
