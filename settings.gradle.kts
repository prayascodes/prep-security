// settings.gradle.kts
pluginManagement {
  val githubUser =
      providers.gradleProperty("gpr.user").orElse(providers.environmentVariable("GITHUB_ACTOR"))

  val githubToken =
      providers.gradleProperty("gpr.key").orElse(providers.environmentVariable("GITHUB_TOKEN"))
  repositories {
    maven {
      setUrl("https://maven.pkg.github.com/prayascodes/maven-releases")
      credentials {
        username = githubUser.orNull
        password = githubToken.orNull
      }
    }
    gradlePluginPortal()
    mavenCentral()
    mavenLocal()
  }
}

dependencyResolutionManagement {
  @Suppress("UnstableApiUsage") repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)

  @Suppress("UnstableApiUsage")
  repositories {
    gradlePluginPortal()
    mavenCentral()
  }
}

plugins {
  id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

rootProject.name = "prep-security"
