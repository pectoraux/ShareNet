plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.androidx.room)
    alias(libs.plugins.ksp)
}

android {
    namespace = "net.sharenet.feed"
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
    room { schemaDirectory("$projectDir/schemas") }
}

dependencies {
    api(project(":core-crypto"))
    api(project(":core-content"))
    api(project(":core-catalog"))
    api(project(":core-transport"))
    api(project(":core-attest"))

    implementation(libs.androidx.core.ktx)
    implementation(libs.coroutines.core)
    implementation(libs.room.runtime)
    implementation(libs.room.ktx)
    implementation(libs.sqlcipher)
    implementation(libs.work.runtime)
    ksp(libs.room.compiler)

    testImplementation(libs.junit)
    testImplementation(libs.truth)
    testImplementation(libs.coroutines.core)
    testImplementation(project(":testing"))
}
