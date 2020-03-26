#!/bin/bash
set -ex

# The compilation process (`mvn compile`) should generate the file below,
# which tells Jenkins which classes from the plugin file to load.
# But sometimes the Visual Studio Code Java support's auto-compile feature
# nukes this file, which makes Jenkins improperly load our plugin.
# If we detect this situation then delete the entire target directory
# so that 'mvn hpi:run' recompiles everything.
if ! [[ -e target/classes/META-INF/annotations/hudson.Extension.txt ]]; then
    rm -rf target
fi

# https://ryanharrison.co.uk/2018/04/29/faster-java-startup-time.html
export JAVA_OPTS="-client -Xverify:none -XX:TieredStopAtLevel=1"

exec mvn -o hpi:run
