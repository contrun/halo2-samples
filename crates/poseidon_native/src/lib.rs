#![no_std]

extern crate alloc;

use alloc::{format, vec::Vec};

use core::marker::PhantomData;
use halo2_gadgets::poseidon::{
    primitives::{ConstantLength, Spec},
    Hash, Pow5Chip, Pow5Config,
};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};

pub use halo2_proofs::arithmetic::Field;
pub use halo2_proofs::halo2curves::bn256::Bn256 as Engine;
pub use halo2_proofs::halo2curves::bn256::Fr as Fp;
pub type ParamsKZG = halo2_proofs::poly::kzg::commitment::ParamsKZG<Engine>;
pub type KZGCommitmentScheme = halo2_proofs::poly::kzg::commitment::KZGCommitmentScheme<Engine>;
pub type VerifyingKey =
    halo2_proofs::plonk::VerifyingKey<halo2_proofs::halo2curves::bn256::G1Affine>;
pub use halo2_proofs::poly::kzg::multiopen::{ProverGWC as Prover, VerifierGWC as Verifier};

#[derive(Clone, Copy)]
pub struct HashCircuit<S, const WIDTH: usize, const RATE: usize, const L: usize>
where
    S: Spec<Fp, WIDTH, RATE> + Clone + Copy,
{
    pub message: Value<[Fp; L]>,
    pub output: Value<Fp>,
    pub _spec: PhantomData<S>,
}

#[derive(Debug, Clone)]
pub struct MyConfig<const WIDTH: usize, const RATE: usize, const L: usize> {
    input: [Column<Advice>; L],
    output: Column<Instance>,
    poseidon_config: Pow5Config<Fp, WIDTH, RATE>,
}

impl<S, const WIDTH: usize, const RATE: usize, const L: usize> Circuit<Fp>
    for HashCircuit<S, WIDTH, RATE, L>
where
    S: Spec<Fp, WIDTH, RATE> + Copy + Clone,
{
    type Config = MyConfig<WIDTH, RATE, L>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            message: Value::unknown(),
            output: Value::unknown(),
            _spec: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let state = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();
        let partial_sbox = meta.advice_column();

        let rc_a = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let rc_b = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();

        meta.enable_constant(rc_b[0]);

        let output = meta.instance_column();
        meta.enable_equality(output);

        Self::Config {
            input: state[..RATE].try_into().unwrap(),
            output,
            poseidon_config: Pow5Chip::configure::<S>(
                meta,
                state.try_into().unwrap(),
                partial_sbox,
                rc_a.try_into().unwrap(),
                rc_b.try_into().unwrap(),
            ),
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip = Pow5Chip::construct(config.poseidon_config.clone());

        let message = layouter.assign_region(
            || "load message",
            |mut region| {
                let message_word = |i: usize| {
                    let value = self.message.map(|message_vals| message_vals[i]);
                    region.assign_advice(
                        || format!("load message_{}", i),
                        config.input[i],
                        0,
                        || value,
                    )
                };

                let message: Result<Vec<_>, Error> = (0..L).map(message_word).collect();
                Ok(message?.try_into().unwrap())
            },
        )?;

        let hasher = Hash::<_, _, S, ConstantLength<L>, WIDTH, RATE>::init(
            chip,
            layouter.namespace(|| "init"),
        )?;
        let output = hasher.hash(layouter.namespace(|| "hash"), message)?;

        layouter.constrain_instance(output.cell(), config.output, 0)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MySpec<const WIDTH: usize, const RATE: usize>;

impl Spec<Fp, 3, 2> for MySpec<3, 2> {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        56
    }

    fn sbox(val: Fp) -> Fp {
        val.pow_vartime([5])
    }

    fn secure_mds() -> usize {
        0
    }
}

impl Spec<Fp, 9, 8> for MySpec<9, 8> {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        56
    }

    fn sbox(val: Fp) -> Fp {
        val.pow_vartime([5])
    }

    fn secure_mds() -> usize {
        0
    }
}

impl Spec<Fp, 12, 11> for MySpec<12, 11> {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        56
    }

    fn sbox(val: Fp) -> Fp {
        val.pow_vartime([5])
    }

    fn secure_mds() -> usize {
        0
    }
}

pub const K: u32 = 6;
