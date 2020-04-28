import * as fs from 'fs'
import * as path from 'path'
import { Circuit } from 'snarkjs'
const compiler = require('circom')
import * as shell from 'shelljs'

import {
    SnarkProvingKey,
    SnarkVerifyingKey,
    parseVerifyingKeyJson,
} from 'libsemaphore'

import {
    hash,
    SnarkBigInt,
    stringifyBigInts,
    unstringifyBigInts,
    IncrementalMerkleTree,
} from 'maci-crypto'

import {
    Keypair,
    PubKey,
    Message,
    StateLeaf,
} from 'maci-domainobjs'

import {
    genNewResultsCommitment,
    genResultCommitmentVerifierCircuitInputs,
} from 'maci-core'

/*
 * @param circuitPath The subpath to the circuit file (e.g.
 *     test/batchProcessMessage_test.circom)
 */
const compileAndLoadCircuit = async (
    circuitPath: string
) => {
    const circuitDef = await compiler(path.join(
        __dirname,
        'circuits',
        `../../circom/${circuitPath}`,
    ))
    return new Circuit(circuitDef)
}

const loadPk = (binName: string): SnarkProvingKey => {
    const p = path.join(__dirname, '../build/' + binName + '.bin')
    return fs.readFileSync(p)
}

const loadVk = (jsonName: string): SnarkVerifyingKey => {
    const p = path.join(__dirname, '../build/' + jsonName + '.json')
    return parseVerifyingKeyJson(fs.readFileSync(p).toString())
}

const genBatchUstProofAndPublicSignals = (witness: any) => {
    return genProofAndPublicSignals(
        witness,
        'batchUstCircuit.json',
        'batchUst.params',
    )
}

const genQvtProofAndPublicSignals = (witness: any) => {
    return genProofAndPublicSignals(
        witness,
        'qvtCircuit.json',
        'qvt.params',
    )
}

const genProofAndPublicSignals = (
    witness: any,
    circuitFilename: string,
    paramsFilename: string,
) => {
    const proofPath = path.join(__dirname, '../build/' + Date.now() + '.proof.json')
    const paramsPath = path.join(__dirname, '../build/', paramsFilename)
    const circuitPath = path.join(__dirname, '../build/', circuitFilename)
    const witnessPath = path.join(__dirname, '../build/' + Date.now() + '.witness.json')
    const publicSignalsPath = path.join(__dirname, '../build/' + Date.now() + '.public.json')

    fs.writeFileSync(witnessPath, JSON.stringify(stringifyBigInts(witness)))

    const cmd = `zkutil prove -c ${circuitPath} -p ${paramsPath} ` +
        `-r ${proofPath} -i ${publicSignalsPath} -w ${witnessPath}`

    shell.exec(cmd)

    const proof = unstringifyBigInts(
        JSON.parse(fs.readFileSync(proofPath).toString())
    )

    const publicSignals = unstringifyBigInts(
        JSON.parse(fs.readFileSync(publicSignalsPath).toString())
    )

    shell.rm('-f', proofPath)
    shell.rm('-f', publicSignalsPath)
    shell.rm('-f', witnessPath)

    return { proof, publicSignals }
}

export {
    compileAndLoadCircuit,
    loadPk,
    loadVk,
    genBatchUstProofAndPublicSignals,
    genQvtProofAndPublicSignals,
}
