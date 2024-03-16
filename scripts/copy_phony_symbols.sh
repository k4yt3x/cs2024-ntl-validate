#!/bin/bash
set -euo pipefail

SOURCE_FILE="data/cataclysm-tiles"
TARGET_FILE="bin/validate"
TEMP_DIR="./temp_section_files"

mkdir -p $TEMP_DIR

copy_section() {
    local SECTION_NAME=$1
    local SECTION_FILE="$TEMP_DIR/${SECTION_NAME}.bin"

    echo "Extracting $SECTION_NAME from $SOURCE_FILE..."
    objcopy --dump-section $SECTION_NAME=$SECTION_FILE $SOURCE_FILE 2>/dev/null

    if [ -f $SECTION_FILE ]; then
        echo "Copying section $SECTION_NAME"
        objcopy --add-section $SECTION_NAME=$SECTION_FILE $TARGET_FILE
    else
        echo "Failed to extract $SECTION_NAME or section does not exist."
    fi
}

# .strtab must be copied before .symtab and .dynsym
copy_section ".strtab"

# copy debug and symbol sections
SECTIONS_TO_COPY=$(readelf -S $SOURCE_FILE | grep -E '\.symtab|\.dynsym|\.debug_' | awk '{print $2}' | grep -v '.strtab')
for SECTION in $SECTIONS_TO_COPY; do
    copy_section "$SECTION"
done

rm -rf $TEMP_DIR

echo "Finished copying specified sections to $TARGET_FILE."

