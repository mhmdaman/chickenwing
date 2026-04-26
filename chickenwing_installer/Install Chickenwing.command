#!/bin/bash

# CHICKENWING BOOTSTRAP INSTALLER (Smart-Path Version)
echo "------------------------------------------"
echo "🚀 CHICKENWING INSTALLER"
echo "------------------------------------------"

# Use the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
APP_NAME="Chickenwing.app"
SOURCE_APP="$SCRIPT_DIR/$APP_NAME"
TARGET_APP="/Applications/$APP_NAME"

# 1. Verify source
if [ ! -d "$SOURCE_APP" ]; then
    echo "❌ Error: $APP_NAME not found at $SOURCE_APP"
    echo "Please make sure $APP_NAME and this script are in the same folder."
    read -p "Press Enter to exit..."
    exit 1
fi

# 2. Deep clean the SOURCE
echo "🛡️  Preparing application..."
xattr -cr "$SOURCE_APP" 2>/dev/null

# 3. Remove old versions
if [ -d "$TARGET_APP" ]; then
    echo "⚠️  Updating existing installation..."
    rm -rf "$TARGET_APP"
fi

# 4. Copy to Applications
echo "📦  Installing to Applications..."
cp -R "$SOURCE_APP" /Applications/

# 5. Final Deep Clean & Sign
echo "🔐  Finalizing security permissions..."
xattr -cr "$TARGET_APP" 2>/dev/null
chmod -R 755 "$TARGET_APP"

# 6. Launch
echo "🚀  Launching Chickenwing..."
open "$TARGET_APP"

echo "------------------------------------------"
echo "✅  DONE! Chickenwing is now ready."
echo "------------------------------------------"
