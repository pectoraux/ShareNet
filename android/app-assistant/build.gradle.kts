plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.ksp)
}

android {
    namespace = "net.sharenet.assistant"
    compileSdk = 34

    defaultConfig {
        applicationId = "net.sharenet.assistant"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "1.0.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables { useSupportLibrary = true }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        isCoreLibraryDesugaringEnabled = true
    }

    kotlinOptions { jvmTarget = "17" }

    buildFeatures { compose = true }

    packaging { resources { excludes += "/META-INF/{AL2.0,LGPL2.1}" } }
}

dependencies {
    coreLibraryDesugaring(libs.desugar)

    implementation(project(":sharenet-sdk"))

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime)
    implementation(libs.androidx.activity.compose)

    // Compose BOM
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.compose.material3)

    implementation(libs.navigation.compose)
    implementation(libs.kotlinx.serialization.json)

    // Room — conversation store
    implementation(libs.room.runtime)
    implementation(libs.room.ktx)
    ksp(libs.room.compiler)

    implementation(libs.datastore)
    implementation(libs.coroutines.core)

    // MediaPipe LLM Inference — real impl uses this; stub compiles without native .so.
    // Uncomment when wiring to device: implementation("com.google.mediapipe:tasks-genai:0.10.14")
    // ONNX Runtime for NLLB / Whisper (translation + ASR) — add when models land
    // implementation("com.microsoft.onnxruntime:onnxruntime:1.19.0")

    // Testing
    testImplementation(libs.junit)
    testImplementation(libs.truth)
    testImplementation(libs.coroutines.core)
    debugImplementation("androidx.compose.ui:ui-tooling:1.7.3")
    debugImplementation("androidx.compose.ui:ui-test-manifest:1.7.3")
}
