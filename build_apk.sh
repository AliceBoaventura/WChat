#!/usr/bin/env bash
set -euo pipefail

# This script installs Android commandline tools (if needed) and builds the debug APK.
# Safe to run on Ubuntu runners or local dev boxes with bash + curl + unzip.

ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$HOME/android-sdk}"
BUILD_TOOLS_VERSION=${BUILD_TOOLS_VERSION:-"34.0.0"}
PLATFORM_VERSION=${PLATFORM_VERSION:-"android-34"}
CMDLINE_VERSION=${CMDLINE_VERSION:-"11076708_latest"}  # r12b as of 2024/2025
GRADLE_CMD=${GRADLE_CMD:-"./gradlew"}

echo "SDK root: $ANDROID_SDK_ROOT"
mkdir -p "$ANDROID_SDK_ROOT"
cd "$ANDROID_SDK_ROOT"

if [ ! -d "cmdline-tools/latest" ]; then
  echo "Installing Android commandline-tools..."
  OS=$(uname -s | tr '[:upper:]' '[:lower:]')
  if [ "$OS" = "darwin" ]; then
    URL="https://dl.google.com/android/repository/commandlinetools-mac-$CMDLINE_VERSION.zip"
  else
    URL="https://dl.google.com/android/repository/commandlinetools-linux-$CMDLINE_VERSION.zip"
  fi
  curl -sSL "$URL" -o cmdline-tools.zip
  mkdir -p cmdline-tools && unzip -q -o cmdline-tools.zip -d cmdline-tools
  # Move to 'latest' to satisfy sdkmanager layout
  mkdir -p cmdline-tools/latest
  mv cmdline-tools/cmdline-tools/* cmdline-tools/latest/ || true
fi

export ANDROID_HOME="$ANDROID_SDK_ROOT"
export PATH="$ANDROID_SDK_ROOT/cmdline-tools/latest/bin:$ANDROID_SDK_ROOT/platform-tools:$ANDROID_SDK_ROOT/build-tools/$BUILD_TOOLS_VERSION:$PATH"

yes | sdkmanager --licenses > /dev/null
sdkmanager "platform-tools" "platforms;$PLATFORM_VERSION" "build-tools;$BUILD_TOOLS_VERSION"

# Back to project root
cd - >/dev/null

# If gradle wrapper is absent, try system gradle; otherwise fail fast.
if [ ! -f "./gradlew" ]; then
  echo "Gradle wrapper not found; attempting to use system gradle."
  if ! command -v gradle >/dev/null 2>&1; then
    echo "No gradle available. Please install gradle or add wrapper to project."
    exit 1
  fi
  GRADLE_CMD="gradle"
else
  chmod +x ./gradlew
fi

$GRADLE_CMD --no-daemon assembleDebug
echo "APK at: app/build/outputs/apk/debug/app-debug.apk"
