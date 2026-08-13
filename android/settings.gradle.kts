pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "sharenet"

include(":core-crypto")
include(":core-content")
include(":core-catalog")
include(":core-transport")
include(":core-attest")
include(":sharenet-sdk")
include(":testing")
include(":app-demo")
include(":app-assistant")
include(":app-wallet")
include(":sharenet-feed")
include(":app-feed")
