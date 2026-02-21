plugins {
    id("java-library")
    id("java-test-fixtures")
    id("signing")
    id("maven-publish")
}

extra["publish"] = true

dependencies {
    compileOnly("org.jetbrains:annotations:26.0.2")
    compileOnly("io.netty:netty-buffer:4.2.10.Final")

    testFixturesImplementation(platform("org.junit:junit-bom:5.11.4"))
    testFixturesImplementation("org.junit.jupiter:junit-jupiter")
    testFixturesApi("io.netty:netty-buffer:4.2.10.Final")
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
