name := """play-java"""

version := "1.0-SNAPSHOT"

lazy val root = (project in file(".")).enablePlugins(PlayJava)

scalaVersion := "2.10.4"

libraryDependencies ++= Seq(
  javaJdbc,
  javaEbean,
  cache,
  javaWs
)

libraryDependencies += "com.dropbox.core" % "dropbox-core-sdk" % "[1.7,1.8)"

libraryDependencies += "com.typesafe" %% "play-plugins-redis" % "2.2.1"

resolvers += "pk11 repo" at "http://pk11-scratch.googlecode.com/svn/trunk"