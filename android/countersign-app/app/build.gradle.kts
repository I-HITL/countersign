import java.util.Properties

plugins {
    id("com.android.application")
}

// Local deployment settings are excluded from source control. Simulation never
// receives these fields or credentials, even when this file is present.
val deployment = Properties().apply {
    rootProject.file("deployment.properties").takeIf { it.isFile }?.inputStream()?.use(::load)
}
fun deploymentString(name: String): String =
    "\"" + deployment.getProperty(name, "")
        .replace("\\", "\\\\").replace("\"", "\\\"")
        .replace("\n", "\\n").replace("\r", "\\r") + "\""
val cloudProjectNumber = deployment.getProperty("cloudProjectNumber", "0").toLongOrNull()
    ?: error("deployment.properties: cloudProjectNumber must be a numeric Google Cloud project number")

android {
    namespace = "com.example.countersign"
    compileSdk = 36
    buildToolsVersion = "36.1.0"

    defaultConfig {
        applicationId = "com.countersign.app"
        // BiometricPrompt.CryptoObject + per-operation
        // setUserAuthenticationParameters need API 30+.
        minSdk = 30
        targetSdk = 36
        versionCode = 2
        versionName = "0.1"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
        create("simulation") {
            initWith(getByName("debug"))
            applicationIdSuffix = ".simulation"
            versionNameSuffix = "-simulation"
            matchingFallbacks += listOf("debug")
        }
        listOf("debug", "release").forEach { name ->
            getByName(name) {
                buildConfigField("String", "BACKEND_URL", deploymentString("backendUrl"))
                buildConfigField("String", "DEVICE_API_TOKEN", deploymentString("deviceApiToken"))
                buildConfigField("long", "CLOUD_PROJECT_NUMBER", "${cloudProjectNumber}L")
            }
        }
    }

    buildFeatures { buildConfig = true }

    // Genuine attestation belongs to both normal builds. Simulation has a
    // separate implementation, so its placeholder token cannot enter release.
    sourceSets {
        getByName("debug").kotlin.directories += "src/real/java"
        getByName("release").kotlin.directories += "src/real/java"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")

    listOf("debugImplementation", "releaseImplementation").forEach {
        add(it, "com.google.android.play:integrity:1.6.0")
        add(it, "org.jetbrains.kotlinx:kotlinx-coroutines-play-services:1.11.0")
    }
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")

    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.11.0")
}
