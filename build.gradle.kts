// mostly yanked from https://github.com/MinnDevelopment/udpqueue.rs/blob/master/build.gradle.kts
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.Files

plugins {
    id("java-library")
    id("maven-publish")
    id("signing")
}

val enablePublishing = false

subprojects {
    group = "moe.kyokobot.libdave"
    version = "1.0-SNAPSHOT"

    // This is applied to all Jar, Zip and Tar tasks.
    tasks.withType<AbstractArchiveTask>().configureEach {
        isPreserveFileTimestamps = false
        isReproducibleFileOrder = true
        // consistent directory permissions, ignoring system's umask
        dirPermissions { unix("755") }
        // consistent file permissions, ignoring system's umask, retaining the executable permission (either 644 or 755)
        eachFile {
            permissions {
                val isExec =
                    Files.getPosixFilePermissions(file.toPath()).contains(PosixFilePermission.OWNER_EXECUTE)
                unix(if (isExec) "755" else "644")
            }
        }
    }

    repositories {
        mavenLocal()
        mavenCentral()
    }

    // See https://github.com/sedmelluq/lavaplayer/blob/master/common/src/main/java/com/sedmelluq/lava/common/natives/architecture/DefaultArchitectureTypes.java
    // identifier is the suffix used after the system name
    fun getPlatform(triplet: String) = when {
        triplet.startsWith("x86_64") && "linux" in triplet && "musl" in triplet -> "linux-musl-x86-64"
        triplet.startsWith("i686") && "linux" in triplet && "musl" in triplet -> "linux-musl-x86"
        triplet.startsWith("aarch64") && "linux" in triplet && "musl" in triplet -> "linux-musl-aarch64"
        triplet.startsWith("arm") && "linux" in triplet && "musl" in triplet -> "linux-musl-arm"

        triplet.startsWith("x86_64") && "linux" in triplet -> "linux-x86-64"
        triplet.startsWith("i686") && "linux" in triplet -> "linux-x86"
        triplet.startsWith("aarch64") && "linux" in triplet -> "linux-aarch64"
        triplet.startsWith("arm") && "linux" in triplet -> "linux-arm"

        triplet.startsWith("x86_64") && "windows" in triplet -> "win-x86-64"
        triplet.startsWith("i686") && "windows" in triplet -> "win-x86"
        triplet.startsWith("aarch64") && "windows" in triplet -> "win-aarch64"
        triplet.startsWith("arm") && "windows" in triplet -> "win-arm"

        "darwin" in triplet -> "darwin"

        else -> throw IllegalArgumentException("Unknown platform: $triplet")
    }

    // Testing: "x86_64-unknown-linux-gnu"
    ext["target"] = findProperty("target") as? String ?: throw AssertionError("Invalid target")
    ext["platform"] = getPlatform(ext["target"].toString())

    val generatePom: MavenPom.() -> Unit = {
        packaging = "jar"
        description.set("Rust implementation of the JDA-NAS interface")
        url.set("https://github.com/MinnDevelopment/udpqueue.rs")
        scm {
            url.set("https://github.com/MinnDevelopment/udpqueue.rs")
            connection.set("scm:git:git://github.com/MinnDevelopment/udpqueue.rs")
            developerConnection.set("scm:git:ssh:git@github.com:MinnDevelopment/udpqueue.rs")
        }
        licenses {
            license {
                name.set("The Apache Software License, Version 2.0")
                url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                distribution.set("repo")
            }
        }
        developers {
            developer {
                id.set("Minn")
                name.set("Florian Spieß")
                email.set("business@minn.dev")
            }
        }
    }

    ext["generatePom"] = generatePom

    val rebuild = tasks.create("rebuild") {
        group = "build"
        afterEvaluate {
            dependsOn(tasks["build"], tasks["clean"])
            tasks["build"].dependsOn(tasks.withType<Jar>())
            tasks.forEach {
                if (it.name != "clean")
                    mustRunAfter(tasks["clean"])
            }
        }
    }

    tasks.withType<PublishToMavenRepository> {
        enabled = enablePublishing
        mustRunAfter(rebuild)
        dependsOn(rebuild)
    }
}
