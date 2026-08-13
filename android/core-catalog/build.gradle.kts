plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.ksp)
}

android {
    namespace = "net.sharenet.catalog"
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
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    api(project(":core-crypto"))
    api(project(":core-content"))

    implementation(libs.androidx.core.ktx)
    implementation(libs.coroutines.core)
    implementation(libs.room.runtime)
    implementation(libs.room.ktx)
    implementation(libs.sqlcipher)
    ksp(libs.room.compiler)

    testImplementation(libs.junit)
    testImplementation(libs.truth)
    testImplementation(libs.coroutines.core)

    androidTestImplementation(libs.androidx.test.runner)
}
