plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.ksp)
}

android {
    namespace = "net.sharenet.transport"
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

    api(libs.nearby.connections)
    implementation(libs.work.runtime)
    implementation(libs.coroutines.core)
    implementation(libs.androidx.core.ktx)
    implementation(libs.datastore)
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")

    testImplementation(libs.junit)
    testImplementation(libs.truth)
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")
    androidTestImplementation(libs.androidx.test.runner)
}
