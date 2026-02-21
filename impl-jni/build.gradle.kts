plugins {
    id("java-library")
    id("signing")
    id("maven-publish")
}

extra["publish"] = true

dependencies {
    compileOnly("org.jetbrains:annotations:26.0.2")
    compileOnly("io.netty:netty-buffer:4.2.10.Final")
    implementation("dev.arbjerg:lava-common:1.5.4")
    api(project(":api"))

    testImplementation(platform("org.junit:junit-bom:5.11.4"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation(testFixtures(project(":api")))
    testImplementation("ch.qos.logback:logback-classic:1.3.16")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testRuntimeOnly(files("../natives/src/main/resources/")) // for the native libraries
}

tasks.test {
    useJUnitPlatform()
}

publishing.publications {
    create<MavenPublication>("Release") {
        from(components["java"])

        groupId = group.toString()
        version = version.toString()

        @Suppress("UNCHECKED_CAST")
        pom.apply(ext["generatePom"] as MavenPom.() -> Unit)
    }
}
