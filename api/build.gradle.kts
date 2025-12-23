plugins {
    id("java-library")
    id("signing")
    id("maven-publish")
}

dependencies {
    compileOnly("org.jetbrains:annotations:26.0.2")
    compileOnly("io.netty:netty-buffer:4.2.9.Final")
}

tasks.test {
    useJUnitPlatform()
}

publishing.publications {
    create<MavenPublication>("Release") {
        from(components["java"])

        groupId = group.toString()
        version = version.toString()

        pom.apply(ext["generatePom"] as MavenPom.() -> Unit)
    }
}
