#!/bin/bash

# This script copies <source_dir> to <destination_dir> and applies environment variable
# substitution, using <env_file>, to any YAML files in <destination_dir>.
# Errors will be raised for any unset variables in YAML files.

# Check args
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <source_dir> <destination_dir> <env_file>"
    exit 1
fi

SRC_DIR="$1"
DEST_DIR="$2"
ENV_FILE="$3"

# Ensure .env file exists
if [ ! -f "$ENV_FILE" ]; then
    echo "Error: Environment file '$ENV_FILE' not found."
    exit 1
fi

# Load environment variables safely from .env file
while IFS='=' read -r key value; do
    if [[ ! "$key" =~ ^# && -n "$key" ]]; then
        export "$key=$value"
    fi
done < "$ENV_FILE"

# Copy directory
cp -ra "$SRC_DIR" "$DEST_DIR"


failure_flag=0

# Process YAMLs
for file in $(find "$DEST_DIR" -name "*.yaml" -type f); do
    # Check file for any unset variables
    missing_vars=$(grep -o '\${[^}]*}' "$file" | tr -d '${}' | sort -u | while read -r var; do
        if [ -z "$(printenv "$var")" ]; then
            echo "$var"
        fi
    done)

    # Raise error on missing vars
    if [ -n "$missing_vars" ]; then
        echo "Error: The following variables in $file are unset:"
        echo "$missing_vars"
        failure_flag=1
    fi

    # Replace environment variables
    envsubst < "$file" > "$file.tmp"
    mv "$file.tmp" "$file"
done

if [ "$failure_flag" -eq 1 ]; then
    echo "Script FAILED to complete in ${DEST_DIR}"
    exit 1
fi

echo "Environment variable substitution complete in ${DEST_DIR}."