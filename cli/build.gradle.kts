plugins {
    kotlin("jvm")
    alias(libs.plugins.kotlinSerialization)
    application
}

dependencies {
    implementation(project(":sdk"))
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.datetime)
    implementation(libs.jline)
    implementation(libs.pdfbox)
}

kotlin {
    jvmToolchain(17)
}

application {
    mainClass.set("dev.carlsen.protondrive.cli.MainKt")
}

tasks.named<JavaExec>("run") {
    // The application plugin doesn't forward stdin by default, which made
    // readLine() return empty immediately - silently "logging in" with an
    // empty username/password instead of prompting.
    standardInput = System.`in`
}
