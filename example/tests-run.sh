#!/bin/sh
#
# Tests the "ssh_key" package by:
#
# 1. Generating an RSA key pair and outputs them as text.
# 2. Parses the public key and outputs it in other representations.
# 3. Parses those other representations and outputs it in the original format.
# 4. Compares the result to see if it is the same as the original public key.
# 5. Repeats steps 2-4 for the private key.
#
#----------------------------------------------------------------

EXE_EXT=$(basename "$0")
EXE_DIR=$(dirname "$0")

OUTPUT_DIR_NAME=output

#----------------------------------------------------------------
# Error handling

# Exit immediately if a simple command exits with a non-zero status.
# Better to abort than to continue running when something went wrong.
set -e

set -u # fail on attempts to expand undefined environment variables

#----------------------------------------------------------------

EXAMPLE_EXE="dart run $EXE_DIR/example.dart"
KEYGEN_EXE="dart run $EXE_DIR/key_generate.dart"

TEST_PUBLIC_KEY_FILE="$EXE_DIR/test-rsa-public-key.pem"

#----------------------------------------------------------------

run_demo() {
  echo "Test public key (PKCS#1 public key format):"
  basename "$TEST_PUBLIC_KEY_FILE"
  echo
  cat "$TEST_PUBLIC_KEY_FILE"

  echo
  echo "Parsed and converted to the old OpenSSH public key format"
  echo
  $EXAMPLE_EXE --public --verbose "$TEST_PUBLIC_KEY_FILE" --openssh
}

#----------------------------------------------------------------

run_all() {
  #----------------
  # Create a directory to store the generated files
  
  local OUTDIR="$EXE_DIR/$OUTPUT_DIR_NAME"

  mkdir -p "$OUTDIR"

  #----------------
  # Generate the public and private key files

  local BASE="$OUTDIR/x"
  
  local FIRST_PUB="$BASE.public"
  local FIRST_PVT="$BASE.private"

  local FIRST_PUB_FORMAT=pkcs1
  local FIRST_PVT_FORMAT=pkcs1

  echo "Generating key pair ($FIRST_PUB and $FIRST_PVT)"

  $KEYGEN_EXE --bitlength 2048 \
              --output "$FIRST_PUB" --force \
              --public $FIRST_PUB_FORMAT --private $FIRST_PVT_FORMAT

  echo

  #----------------
  # Convert and check public key formats

  echo "PUBLIC KEY"
  echo
  
  for FORMAT in openssh sshpublickey pkcs1 x509spki; do
    local CONVERTED="$BASE-$FORMAT.public"
    local CHECK="$BASE-${FORMAT}_check.public"

    echo "$FORMAT:"
    echo "  Converting to $FORMAT ($CONVERTED)"
    
    $EXAMPLE_EXE --public --$FORMAT "$FIRST_PUB" > "$CONVERTED"

    if [ $? -eq 0 ]; then
      echo "  Checking round-trip conversion"
      $EXAMPLE_EXE --public --$FIRST_PUB_FORMAT "$CONVERTED" > "$CHECK"
      diff -q "$FIRST_PUB" "$CHECK"
    fi
    
    echo
  done

  #----------------
  # Convert and check private key formats

  echo "PRIVATE KEY"
  echo
  
  for FORMAT in openssh puttyprivatekey pkcs1; do
    local CONVERTED="$BASE-$FORMAT.private"
    local CHECK="$BASE-${FORMAT}_check.private"

    echo "$FORMAT:"
    echo "  Converting to $FORMAT ($CONVERTED)"
    
    $EXAMPLE_EXE --private --$FORMAT "$FIRST_PVT" > "$CONVERTED"

    if [ $? -eq 0 ]; then
      echo "  Checking round-trip conversion"
      $EXAMPLE_EXE --private --$FIRST_PVT_FORMAT "$CONVERTED" > "$CHECK"
      diff -q "$FIRST_PVT" "$CHECK"
    fi

    echo
  done
}

#----------------------------------------------------------------
# Process command line arguments

COMMAND=

if [ $# -eq 1 ]; then
  COMMAND="$1"
fi

case $COMMAND in
  demo)
    run_demo
    ;;
  all)
    run_all
    ;;
  *)
    cat <<EOF
Usage: $0 command
Commands:
  demo   - run example.dart on the test public key
  all    - run comprehensive test
EOF
    exit 2
esac

#EOF
