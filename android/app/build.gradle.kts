plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("com.chaquo.python")
}

// The Python engine is the very same package as the CLI/TUI/GUI: copy it in at build time.
val syncPython by tasks.registering(Copy::class) {
    from(rootProject.file("../filterscope")) {
        exclude("**/__pycache__/**", "scripts/**")
    }
    into(layout.projectDirectory.dir("src/main/python/filterscope"))
}
tasks.named("preBuild") { dependsOn(syncPython) }
tasks.configureEach {
    if (name.contains("PythonSources") || name.startsWith("merge") && name.contains("Python")) dependsOn(syncPython)
}

android {
    namespace = "org.tunnelmoth.filterscope"
    compileSdk = 34

    defaultConfig {
        applicationId = "org.tunnelmoth.filterscope"
        minSdk = 24
        targetSdk = 34
        versionCode = 3200
        versionName = "3.2.0"
        ndk {
            // Python 3.12+ on Chaquopy is 64-bit only.
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    signingConfigs {
        create("release") {
            // Self-signed key for sideload updates. Trust the GitHub release + SHA256SUMS, not this key.
            storeFile = file("../keystore/filterscope.jks")
            storePassword = "filterscope"
            keyAlias = "filterscope"
            keyPassword = "filterscope"
        }
    }
    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("release")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures { compose = true }
    packaging { resources.excludes += "/META-INF/{AL2.0,LGPL2.1}" }
}

chaquopy {
    defaultConfig {
        version = "3.13"
        pip {
            install("requests")
            install("dnspython")
            install("cryptography")
            install("certifi")
            install("rich")
        }
    }
}

dependencies {
    val bom = platform("androidx.compose:compose-bom:2024.09.03")
    implementation(bom)
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material:material-icons-core")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    debugImplementation("androidx.compose.ui:ui-tooling")
}
