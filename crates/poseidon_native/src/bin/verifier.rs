use halo2_gadgets::poseidon::primitives::Spec;
use halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_proofs::transcript::TranscriptReadBuffer;
use halo2_proofs::{
    plonk::verify_proof,
    poly::commitment::Params,
    transcript::{Blake2bRead, Challenge255},
    SerdeFormat,
};
use poseidon_natives::{
    Engine, Fp, HashCircuit, KZGCommitmentScheme, MySpec, ParamsKZG, Verifier, VerifyingKey,
};

fn verify_poseidon<S, const WIDTH: usize, const RATE: usize, const L: usize>(
    proof: &[u8],
    output_data: &[u8],
    params_data: &[u8],
    vk_data: &[u8],
) -> Result<(), String>
where
    S: Spec<Fp, WIDTH, RATE> + Copy + Clone,
{
    // Initialize the polynomial commitment parameters
    let params: ParamsKZG = Params::read(&mut &params_data[..]).map_err(|e| e.to_string())?;

    // Initialize the verifying key
    let vk: VerifyingKey = VerifyingKey::read::<_, HashCircuit<S, WIDTH, RATE, L>>(
        &mut &vk_data[..],
        SerdeFormat::RawBytes,
    )
    .map_err(|e| e.to_string())?;

    if output_data.len() != 32 {
        return Err(format!("Invalid output data length: {}", output_data.len()));
    }
    let output = {
        let mut raw = [0u64; 4];
        for i in 0..32 {
            raw[i / 8] |= (output_data[i] as u64) << ((i % 8) * 8);
        }
        Fp::from_raw(raw)
    };

    let strategy = SingleStrategy::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    verify_proof::<
        KZGCommitmentScheme,
        Verifier<'_, Engine>,
        Challenge255<_>,
        Blake2bRead<_, _, Challenge255<_>>,
        SingleStrategy<'_, _>,
    >(&params, &vk, strategy, &[&[&[output]]], &mut transcript)
    .map_err(|e| e.to_string())
}

fn main() {
    let proof = std::fs::read("proof.bin").expect("read");
    let output_data = std::fs::read("output.bin").expect("read");
    let params_data = std::fs::read("params.bin").expect("read");
    let vk_data = std::fs::read("vk.bin").expect("read");

    verify_poseidon::<MySpec<3, 2>, 3, 2, 2>(&proof, &output_data, &params_data, &vk_data)
        .expect("verify");

    println!("Success!");
}
