plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.ksp)
}

android {
    namespace = "net.sharenet.sdk"
    compileSdk = 34

    defaultConfig {
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    api(project(":core-crypto"))
    api(project(":core-content"))
    api(project(":core-catalog"))
    api(project(":core-transport"))
    api(project(":core-attest"))
    api(project(":testing"))

    implementation(libs.room.runtime)
    implementation(libs.room.ktx)
    ksp(libs.room.compiler)

    implementation(libs.coroutines.core)
    implementation(libs.androidx.core.ktx)
    implementation(libs.datastore)
    implementation(libs.work.runtime)

    testImplementation(libs.junit)
    testImplementation(libs.truth)
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")
}
