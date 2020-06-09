plugins {
    kotlin("jvm")
    application
}

application {
    mainClassName = "pcclark4.kntlm.sample.MainKt"
}

dependencies {
    implementation(kotlin("stdlib"))
    implementation(project(":kntlm"))
    implementation("com.squareup.okhttp3:okhttp:4.7.2")
}
