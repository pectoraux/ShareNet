plugins {
    id("java-library")
}
group = "net.sharenet"
version = "0.1.0"
java { sourceCompatibility = JavaVersion.VERSION_1_8; targetCompatibility = JavaVersion.VERSION_1_8 }
repositories { mavenCentral() }
dependencies {
    compileOnly("com.github.martinpaljak:javacard:3.0.5") // JavaCard API
    testImplementation("com.licel:jcardsim:3.0.5.11") // jCardSim
    testImplementation("junit:junit:4.13.2")
    testImplementation("com.google.truth:truth:1.4.4")
}
tasks.withType<Test> { useJUnit() }
