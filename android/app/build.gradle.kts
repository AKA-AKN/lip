// 1. Add the import at the very top to bypass the 'java' keyword conflict
import java.util.Properties

plugins {
    id("com.android.application")
    id("kotlin-android")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

// 2. Safely load the properties
val localProperties = Properties()
val localPropertiesFile = rootProject.file("local.properties")
if (localPropertiesFile.exists()) {
    localPropertiesFile.inputStream().use { localProperties.load(it) }
}
val myRpId: String = localProperties.getProperty("rp_id") ?: "localhost"

android {
    namespace = "com.example.lip_app"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    // Enable BuildConfig so Kotlin can read our secure domain
    buildFeatures {
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    // 3. Fix the deprecation warning using the modern toolchain
    kotlin {
        jvmToolchain(17)
    }

    defaultConfig {
        applicationId = "com.example.lip_app"
        minSdk = flutter.minSdkVersion
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName

        // Inject the secure domain variables
        buildConfigField("String", "RP_ID", "\"$myRpId\"")
        manifestPlaceholders["rpId"] = myRpId
        resValue("string", "asset_statements", "[{\\\"include\\\": \\\"https://$myRpId/.well-known/assetlinks.json\\\"}]")
    }

    buildTypes {
        release {
            signingConfig = signingConfigs.getByName("debug")
        }
    }
}

flutter {
    source = "../.."
}

dependencies {
    implementation("com.yubico.yubikit:android:3.0.1")
    implementation("com.yubico.yubikit:core:3.0.1")
    implementation("com.yubico.yubikit:fido:3.0.1")
}