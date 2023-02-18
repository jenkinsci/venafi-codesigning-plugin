# Development guide

## Development environment setup

Requirements:

* Java >= 11 (openjdk 11.0.16 2022-07-19)
* Maven

To start a development Jenkins instance with this plugin loaded, run:

~~~bash
./devscripts/run.sh
~~~

You can then access Jenkins on http://127.0.0.1:8080/jenkins/

## Troubleshooting: Jenkins can't find a particular function

### Cause

The build process (`mvn compile`) generates `target/classes/META-INF/annotations/hudson.Extension.txt`, which tells Jenkins which classes from the plugin file to load. Sometimes Visual Studio Code's Java support's auto-build feature (which doesn't use Maven under the hood) nukes this file, which makes Jenkins improperly load our plugin.

This can normally be solved by fully rebuilding the project (`mvn clean && mvn compile`). But Visual Studio Code sometimes enters an infinite auto-build loop, it which it tries to build the project over and over again. The Java support's auto-build feature builds all the Java files continuously (while not generating `hudson.Extension.txt`), so that `mvn compile` believes that there's nothing to do. As a result, `hudson.Extension.txt` is never generated.

You can check whether there's an auto-build loop by invoking the "Java: Show Build Job Status" command.

### Solution

1. Run the "Java: Clean Java Language Server Workspace" command to stop the auto-build loop.
2. Run `mvn clean && mvn compile`

## Release

~~~bash
mvn release:prepare
mvn release:perform
git push
~~~
