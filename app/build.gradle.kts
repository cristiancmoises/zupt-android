plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "co.securityops.zupt"
    compileSdk = 34

    defaultConfig {
        applicationId = "co.securityops.zupt"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "1.0.0"
        resourceConfigurations += listOf("en")
        vectorDrawables.useSupportLibrary = true
    }

    signingConfigs {
        create("release") {
            val ksPath = System.getenv("ZUPT_KEYSTORE") ?: "../zupt-release.keystore"
            val ksPass = System.getenv("ZUPT_KS_PASS") ?: "zuptzupt"
            val ksAlias = System.getenv("ZUPT_KS_ALIAS") ?: "zupt"
            val ksKeyPass = System.getenv("ZUPT_KS_KEY_PASS") ?: "zuptzupt"
            storeFile = file(ksPath)
            storePassword = ksPass
            keyAlias = ksAlias
            keyPassword = ksKeyPass
        }
    }

    buildTypes {
        debug {
            applicationIdSuffix = ".debug"
            isMinifyEnabled = false
        }
        release {
            isMinifyEnabled = false
            isShrinkResources = false
            signingConfig = signingConfigs.getByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources {
            excludes += setOf(
                "/META-INF/{AL2.0,LGPL2.1}",
                "/META-INF/DEPENDENCIES",
                "/META-INF/LICENSE*",
                "/META-INF/NOTICE*",
                "/META-INF/*.kotlin_module"
            )
        }
    }

    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.09.02")
    implementation(composeBom)

    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.2")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.6")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.6")
    implementation("androidx.documentfile:documentfile:1.0.1")
    implementation("androidx.navigation:navigation-compose:2.8.1")

    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.compose.animation:animation")

    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")

    debugImplementation("androidx.compose.ui:ui-tooling")
}
