#!/usr/bin/env sh

##############################################################################
# Gradle start up script for UN*X
##############################################################################

APP_BASE_NAME=${0##*/}
APP_HOME=$(dirname "$0")
APP_HOME=$(cd "$APP_HOME" && pwd)

exec "$APP_HOME/gradle/wrapper/gradle-wrapper.jar" 2>/dev/null >/dev/null
