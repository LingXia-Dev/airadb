#!/bin/sh
# Rebuild helper.dex (checked in; Cargo does not run this). Needs a JDK and
# the Android SDK with platforms;android-21 and build-tools.
set -e
cd "$(dirname "$0")"
SDK="${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}"
BT="$(ls -d "$SDK"/build-tools/* | sort -V | tail -1)"
OUT="$(mktemp -d)"
javac --release 8 -cp "$SDK/platforms/android-21/android.jar" -d "$OUT" src/airadb/Helper.java
"$BT/d8" --min-api 21 --release --lib "$SDK/platforms/android-21/android.jar" --output "$OUT" "$OUT"/airadb/*.class
cp "$OUT/classes.dex" helper.dex
rm -rf "$OUT"
ls -l helper.dex
