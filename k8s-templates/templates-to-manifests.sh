#!/bin/bash

# This will copy <source_dir> to <destination_dir> then apply environment var
# substitution, using [env_file], to any yamls in <destination_dir>. Warnings
# will be raised for any variables found in yaml files that do not exist in
# the [env_file].

# Check args
if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <source_dir> <destination_dir> [env_file]"
    exit 1
fi

SRC_DIR="$1"
DEST_DIR="$2"
ENV_FILE="$3"

# Load environment variables from .env file
if [ -n "$ENV_FILE" ] && [ -f "$ENV_FILE" ]; then
    export $(grep -v '^#' "$ENV_FILE" | xargs)
fi

# Copy directory structure
find $SRC_DIR/* -type d | xargs mkdir -p
rsync -a -f '+ */' -f '- *' "$SRC_DIR/" "$DEST_DIR/"

# Find and process files
find "$SRC_DIR" -name "*.yaml" -type f | while read -r file; do
    dest_file="$DEST_DIR${file#$SRC_DIR}"
    cp "$file" "$dest_file"

    # Warn about any unset variables
    missing_vars=$(grep -o '\${[^}]*}' "$dest_file" | tr -d '${}' | sort -u | while read -r var; do
        if [ -z "$(printenv "$var")" ]; then
            echo "$var"
        fi
    done)

    if [ -n "$missing_vars" ]; then
        echo "Warning: The following variables in $dest_file are unset and will not be substituted:"
        echo "$missing_vars"
    fi

    # Replace environment variables
    envsubst < "$dest_file" > "$dest_file.tmp"
    mv "$dest_file.tmp" "$dest_file"
done

echo "Environment variable substitution complete in ${DEST_DIR}."
