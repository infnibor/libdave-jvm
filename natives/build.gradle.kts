import org.gradle.kotlin.dsl.register
import java.net.URL
import javax.net.ssl.HttpsURLConnection

plugins {
    id("java-library")
    id("signing")
    id("maven-publish")
}

dependencies {
    api(project(":api"))
    api(project(":impl-jni"))
}

val processResources: Copy by tasks
val target = ext["target"]?.toString() ?: ""
val platform = ext["platform"] as String
val artifactName = "natives-$platform"

// This checks if the version already exists on maven central, and skips if a successful response is returned.
val shouldPublish by lazy {
//    val conn =
//        URL("https://repo1.maven.org/maven2/club/minnced/$artifactName/$version/").openConnection() as HttpsURLConnection
//    conn.requestMethod = "GET"
//    conn.connect()
//
//    conn.responseCode > 400
    false
}

tasks.withType<Jar> {
    archiveBaseName.set(artifactName)
}

tasks.register<Copy>("moveResources") {
    group = "build"

    from("cmake-build-$target/")

    include {
        it.name == "libdave-jvm.so" || it.name == "libdave-jvm.dylib" || it.name == "dave-jvm.dll"
    }

    into("src/main/resources/natives/$platform")

    processResources.dependsOn(this)
}

tasks.register<Delete>("cleanNatives") {
    group = "build"
    delete(fileTree("src/main/resources/natives"))
    tasks["clean"].dependsOn(this)
}

processResources.include {
    it.isDirectory || it.file.parentFile.name == platform
}


publishing.publications {
    create<MavenPublication>("Release") {
        from(components["java"])

        groupId = group.toString()
        artifactId = artifactName
        version = version.toString()

        pom.apply(ext["generatePom"] as MavenPom.() -> Unit)
        pom.name.set(artifactName)
    }
}

val signingKey: String? by project
val signingPassword: String? by project

if (signingKey != null) {
    signing {
        useInMemoryPgpKeys(signingKey, signingPassword ?: "")
        val publications = publishing.publications.toTypedArray()
        sign(*publications)
    }
} else {
    println("Could not find signingKey")
}

// Only run publishing tasks if the version doesn't already exist

tasks.withType<PublishToMavenRepository> {
    enabled = enabled && shouldPublish
}
