#!/usr/bin/env sh

SCRIPT_DIR=$( dirname -- "$BASH_SOURCE"; )
DIR=$(realpath "${SCRIPT_DIR}/validator_keys")
PROJECT_DIR=$(realpath "${SCRIPT_DIR}/../..")

FILE="$(ls $DIR/deposit_data*.json | sort -V | tail -n1)"
echo $PROJECT_DIR

if test -f "$FILE"; then
    cd $PROJECT_DIR && go run examples/use-dkg.go $FILE
else
  echo "deposit_data-[timestamp].json file is not found in $DIR."
fi