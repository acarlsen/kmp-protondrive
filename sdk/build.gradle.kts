import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.kotlinSerialization)
    alias(libs.plugins.androidLibrary)
    alias(libs.plugins.mavenPublish)
}

group = "dev.carlsen.protondrive"
version = "1.0.0-beta01"

kotlin {
    jvmToolchain(17)

    compilerOptions {
        freeCompilerArgs.add("-Xexpect-actual-classes")
    }

    jvm()
    android {
        withHostTest {}
        namespace = "dev.carlsen.protondrive"
        compileSdk = 37
        minSdk = 26
        compilerOptions {
            jvmTarget = JvmTarget.JVM_17
        }
    }

    applyDefaultHierarchyTemplate()

    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation(libs.kotlinx.coroutines.core)

                api(libs.kotlinx.serialization.json)
                api(libs.kotlinx.io.core)
                api(libs.kotlinx.datetime)
                api(libs.bignum)
                api(libs.ktor.client.core)
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(libs.kotlin.test)
                implementation(libs.kotlinx.coroutines.test)
            }
        }

        val jvmAndroid by creating {
            dependsOn(commonMain)
            dependencies {
                implementation(libs.bcrypt)
                api(libs.pgpainless.core)
            }
        }
        val jvmAndroidTest by creating {
            dependsOn(commonTest)
        }

        androidMain.get().apply {
            dependsOn(jvmAndroid)
            dependencies {
                // OkHttp rather than CIO on Android: Conscrypt-backed TLS, HTTP/2, and the
                // platform-standard connection pooling - CIO's pure-Kotlin TLS is noticeably
                // slower there.
                implementation(libs.ktor.client.okhttp)
            }
        }
        jvmMain.get().apply {
            dependsOn(jvmAndroid)
            dependencies {
                implementation(libs.ktor.client.cio)
            }
        }
        jvmTest.get().dependsOn(jvmAndroidTest)
    }
}
