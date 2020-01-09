# Makefile

DIST_DIR=dist

.PHONY: help dartfmt dartdoc

help:
	@echo "Make targets:"
	@echo "  dartfmt  - reformat code"
	@echo "  dartdoc  - generate documentation"
	@echo "  clean    - delete generated files"

# ssh-keygen -t rsa -b 2048 -f rsa2048
# ssh-keygen -t rsa -b 4096 -f rsa4096
# ssh-keygen  -e -m rfc4716 -f rsa2048.pub > rsa2048.rfc4716
# ssh-keygen  -e -m pkcs8 -f rsa2048.pub > rsa2048.pkcs8
# ssh-keygen  -e -m pem -f rsa2048.pub > rsa2048.pem

#----------------------------------------------------------------
# Development targets

dartfmt:
	@dartfmt -w lib test examples | grep -v ^Unchanged

#----------------------------------------------------------------
# Documentation

# Dart source code documentation

dartdoc:
	@dartdoc --output "${DIST_DIR}/doc/code"
	@echo "View Dart documentation by opening: ${DIST_DIR}/doc/code/index.html"


clean:
	rm -rf "${DIST_DIR}"
