plugins {
    // Pure Kotlin JVM — no Android plugin, so tests run on the JVM without an emulator.
    kotlin("jvm")
}

dependencies {
    api("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")
    api("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")
    implementation("junit:junit:4.13.2")
    implementation("com.google.truth:truth:1.4.4")
    // No Android dependencies. No play-services-nearby. No Room.
}

kotlin { jvmToolchain(17) }
