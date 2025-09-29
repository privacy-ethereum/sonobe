#!/bin/bash
BASEDIR=$(dirname "$0")
circom ${BASEDIR}/cubic_circuit.circom --r1cs --sym --wasm --prime bn128 --output ${BASEDIR}/
circom ${BASEDIR}/with_external_inputs.circom --r1cs --sym --wasm --prime bn128 --output ${BASEDIR}/
circom ${BASEDIR}/no_external_inputs.circom --r1cs --sym --wasm --prime bn128 --output ${BASEDIR}/
