use ckb_hash::blake2b_256;
use ckb_jsonrpc_types::JsonBytes;
use ckb_mock_tx_types::ReprMockTransaction;
use ckb_types::H256;
use core::marker::PhantomData;
use halo2_gadgets::poseidon::primitives::{self as poseidon, ConstantLength, Spec};
use halo2_proofs::halo2curves::bn256::G1Affine;
use halo2_proofs::transcript::TranscriptWriterBuffer;
use halo2_proofs::{
    circuit::Value,
    plonk::{create_proof, keygen_pk, keygen_vk},
    poly::commitment::Params,
    transcript::{Blake2bWrite, Challenge255},
    SerdeFormat,
};
use poseidon_natives::{
    Engine, Fp, HashCircuit, KZGCommitmentScheme, MySpec, ParamsKZG, Prover, VerifyingKey, K,
};
use rand::rngs::OsRng;
use serde_json::{from_str, to_string_pretty};

fn run_poseidon<S, const WIDTH: usize, const RATE: usize, const L: usize>(
    preimage: Vec<u8>,
) -> Result<(Vec<u8>, Fp, ParamsKZG, VerifyingKey), String>
where
    S: Spec<Fp, WIDTH, RATE> + Copy + Clone,
{
    let max_length = L * 32;
    if preimage.len() > max_length {
        return Err(format!(
            "Preimage length {} exceeds maximum length {}!",
            preimage.len(),
            max_length
        ));
    }

    let mut message = [Fp::zero(); L];
    for i in 0..((preimage.len() + 31) / 32) {
        let start = i * 32;
        let count = core::cmp::min(32, preimage.len() - start);
        let mut data = [0u64; 4];
        for j in 0..count {
            data[j / 8] |= (preimage[start + j] as u64) << ((j % 8) * 8);
        }
        message[i] = Fp::from_raw(data);
    }
    let output = poseidon::Hash::<Fp, S, ConstantLength<L>, WIDTH, RATE>::init().hash(message);

    // Initialize the polynomial commitment parameters
    let params = ParamsKZG::setup(K, OsRng);
    let empty_circuit = HashCircuit::<S, WIDTH, RATE, L> {
        message: Value::unknown(),
        output: Value::unknown(),
        _spec: PhantomData,
    };

    // Initialize the proving key
    let vk = keygen_vk(&params, &empty_circuit).map_err(|e| e.to_string())?;
    let pk = keygen_pk(&params, vk.clone(), &empty_circuit).map_err(|e| e.to_string())?;

    let mut rng = OsRng;
    let circuit = HashCircuit::<S, WIDTH, RATE, L> {
        message: Value::known(message),
        output: Value::known(output),
        _spec: PhantomData,
    };

    // Create a proof
    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<G1Affine>>::init(vec![]);
    create_proof::<KZGCommitmentScheme, Prover<'_, Engine>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[&[output]]],
        &mut rng,
        &mut transcript,
    )
    .map_err(|e| e.to_string())?;
    let proof = transcript.finalize();

    Ok((proof, output, params, vk))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        println!("Usage: {} <preimage> <verifier binary>", args[0]);
        return;
    }

    let preimage = args[1].as_bytes().to_vec();
    let (proof, output, params, vk) = run_poseidon::<MySpec<3, 2>, 3, 2, 2>(preimage).expect("run");
    let output_data: [u8; 32] = output.into();

    std::fs::write("output.bin", &output_data).expect("write");
    std::fs::write("proof.bin", &proof).expect("write");

    let mut params_data = vec![];
    params.write(&mut params_data).expect("write");
    std::fs::write("params.bin", &params_data).expect("write");

    let mut vk_data = vec![];
    vk.write(&mut vk_data, SerdeFormat::RawBytes)
        .expect("write");
    std::fs::write("vk.bin", &vk_data).expect("write");

    build_ckb_tx(&proof, &output_data, &params_data, &vk_data, &args[2]);
}

fn build_ckb_tx(proof: &[u8], output: &[u8], params: &[u8], vk: &[u8], binary_name: &str) {
    let mut tx: ReprMockTransaction =
        from_str(&String::from_utf8_lossy(include_bytes!("./dummy_tx.json"))).expect("json");

    tx.tx.witnesses[0] = JsonBytes::from_vec(params.to_vec());
    tx.tx.witnesses[1] = JsonBytes::from_vec(vk.to_vec());
    tx.tx.witnesses[2] = JsonBytes::from_vec(proof.to_vec());
    tx.tx.witnesses[3] = JsonBytes::from_vec(output.to_vec());

    let binary = std::fs::read(binary_name).expect("read");
    let hash = blake2b_256(&binary).to_vec();

    tx.mock_info.inputs[0].output.lock.code_hash = H256::from_slice(&hash).expect("H256");
    tx.mock_info.cell_deps[0].data = JsonBytes::from_vec(binary);

    let json = to_string_pretty(&tx).expect("json");
    std::fs::write("tx.json", &json).expect("write");
}
