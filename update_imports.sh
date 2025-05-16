#!/bin/bash
# Script to update GitHub references from maheshdj to ExclusiveAccount

# Find all Go files
FILES=$(find . -name "*.go")

# Update references in each file
for FILE in $FILES; do
  echo "Updating $FILE"
  sed -i 's|github.com/maheshdj/iot-scanner|github.com/ExclusiveAccount/iot-scanner|g' "$FILE"
done

echo "All imports updated successfully!"
