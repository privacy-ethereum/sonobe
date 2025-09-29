#!/bin/bash
BASEDIR="$(dirname "$(realpath "$0")")"
for test_path in test_circuit test_mimc test_no_external_inputs; do
	FOLDER="${BASEDIR}/${test_path}/"
	cd ${FOLDER} && nargo compile && cd ${BASEDIR}
done
