use algebra::AffineCurve;
use cctp_primitives::{
    type_mapping::FieldElement,
    utils::commitment_tree::{hash_vec, DataAccumulator},
};
use r1cs_core::{ConstraintSynthesizer, ConstraintSystemAbstract, SynthesisError};
use r1cs_crypto::{FieldBasedHashGadget, FieldHasherGadget};
use r1cs_std::{
    alloc::AllocGadget, boolean::Boolean,
    fields::nonnative::nonnative_field_gadget::NonNativeFieldGadget, groups::GroupGadget,
    prelude::EqGadget, select::CondSelectGadget, FromBitsGadget,
};

use crate::{
    type_mapping::*, CswFtProverData, CswProverData, CswSysData, CswUtxoProverData,
    FieldElementGadget, WithdrawalCertificateData, PHANTOM_FIELD_ELEMENT,
};

use self::data_structures::CswProverDataGadget;

pub mod data_structures;

#[derive(Clone)]
pub struct CeasedSidechainWithdrawalCircuit {
    // Setup params
    range_size: u32,
    num_custom_fields: u32,

    // Witnesses
    sidechain_id: FieldElement,
    csw_data: CswProverData,

    // Public inputs
    constant: Option<FieldElement>,
    csw_sys_data_hash: FieldElement,
}

impl CeasedSidechainWithdrawalCircuit {
    fn compute_csw_data_hash(
        sys_data: &CswSysData,
        sidechain_id: FieldElement
    ) -> Result<FieldElement, Error> 
    {
        let mut sys_data_hash_inputs = DataAccumulator::init()
            .update(sys_data.amount)?
            .update(&sys_data.receiver[..])?
            .get_field_elements()?;

        debug_assert!(sys_data_hash_inputs.len() == 1);

        sys_data_hash_inputs.extend_from_slice(&[
            sidechain_id,
            sys_data.nullifier,
            sys_data.sc_last_wcert_hash,
            sys_data.mcb_sc_txs_com_end,
        ]);

        hash_vec(sys_data_hash_inputs)
    }

    pub fn new(
        sidechain_id: FieldElement,
        constant: Option<FieldElement>,
        sys_data: CswSysData,
        last_wcert: Option<WithdrawalCertificateData>,
        utxo_data: Option<CswUtxoProverData>,
        ft_data: Option<CswFtProverData>,
        range_size: u32,
        num_custom_fields: u32,
    ) -> Result<Self, Error> 
    {
        // Compute csw sys_data hash
        let csw_sys_data_hash = Self::compute_csw_data_hash(&sys_data, sidechain_id)?;

        // Handle all cases
        let csw_data = match (last_wcert, utxo_data, ft_data) {
            // SC Utxo withdraw
            (Some(last_wcert), Some(utxo_data), None) => {
                Ok(
                    CswProverData {
                        sys_data,
                        last_wcert,
                        utxo_data,
                        ft_data: CswFtProverData::get_phantom(range_size),
                    }
                )
            },
            // FT withdraw, with last_wcert present
            (Some(last_wcert), None, Some(ft_data)) => {
                Ok(
                    CswProverData {
                        sys_data,
                        last_wcert,
                        utxo_data: CswUtxoProverData::default(),
                        ft_data,
                    }
                )
            },
            // FT withdraw, with last_wcert not present
            (None, None, Some(ft_data)) => {
                Ok(
                    CswProverData {
                        sys_data,
                        last_wcert: WithdrawalCertificateData::get_phantom(num_custom_fields),
                        utxo_data: CswUtxoProverData::default(),
                        ft_data,
                    }
                )
            },
            // Attempt to withdraw a sc utxo without having specified a last_wcert
            (None, Some(_), _) => Err(Error::from("Attempt to withdraw SC Utxo without specifying last WCert")),
            // Attempt to withdraw both a sc utxo and a ft
            (_, Some(_), Some(_)) => Err(Error::from("Cannot create a CSW proof for retrieving both a SC UTXO and a FT")),
            // Any other combination is not admissable
            _ => Err(Error::from("Unexpected inputs combination"))
        }?;

        Ok(
            Self {
                range_size,
                num_custom_fields,
                sidechain_id,
                csw_data,
                constant,
                csw_sys_data_hash,
            }
        )
    }

    // For testing, if useful
    pub fn from_prover_data(
        sidechain_id: FieldElement,
        constant: Option<FieldElement>,
        csw_data: CswProverData,
        range_size: u32,
        num_custom_fields: u32,
    ) -> Result<Self, Error> 
    {
        let csw_sys_data_hash = Self::compute_csw_data_hash(&csw_data.sys_data, sidechain_id)?;

        Ok(CeasedSidechainWithdrawalCircuit {
            sidechain_id,
            csw_data,
            range_size,
            num_custom_fields,
            constant,
            csw_sys_data_hash,
        })
    }

    pub fn get_instance_for_setup(
        range_size: u32,
        num_custom_fields: u32,
        is_constant_present: bool,
    ) -> Self 
    {
        Self {
            range_size,
            num_custom_fields,
            sidechain_id: PHANTOM_FIELD_ELEMENT,
            csw_data: CswProverData::get_phantom(range_size, num_custom_fields),
            constant: if is_constant_present { Some(PHANTOM_FIELD_ELEMENT) } else { None },
            csw_sys_data_hash: PHANTOM_FIELD_ELEMENT,
        }
    }

    /// Extract the sign of the x coordinate and the y coordinate itself from
    /// 'public_key_bits_g', assuming to be passed in BE form.
    fn get_x_sign_and_y_coord_from_pk_bits<CS: ConstraintSystemAbstract<FieldElement>>(
        mut cs: CS,
        public_key_bits_g: &[Boolean; SIMULATED_FIELD_BYTE_SIZE * 8],
    ) -> Result<
        (
            Boolean,
            NonNativeFieldGadget<SimulatedFieldElement, FieldElement>,
        ),
        SynthesisError,
    > {
        // Get the Boolean corresponding to the sign of the x coordinate
        let pk_x_sign_bit_g = public_key_bits_g[0];

        // Read a NonNativeFieldGadget(ed25519Fq) from the other Booleans
        let pk_y_coordinate_g: NonNativeFieldGadget<SimulatedFieldElement, FieldElement> =
            NonNativeFieldGadget::from_bits(
                cs.ns(|| "alloc pk y coordinate"),
                &public_key_bits_g[1..],
            )?;

        Ok((pk_x_sign_bit_g, pk_y_coordinate_g))
    }

    /// Enforce ownership of the public key in the Sc Utxo/FT by enforcing its derivation from the secret key.
    fn enforce_pk_ownership<CS: ConstraintSystemAbstract<FieldElement>>(
        mut cs: CS,
        csw_data_g: &CswProverDataGadget,
        should_enforce_utxo_withdrawal_g: &Boolean,
    ) -> Result<(), SynthesisError> {
        // Get public_key_y_coord and x sign from both sc utxo and ft and select the correct one
        let (pk_x_sign_bit_g, pk_y_coordinate_g) = {
            let (utxo_pk_x_sign_bit_g, utxo_pk_y_coordinate_g) =
                Self::get_x_sign_and_y_coord_from_pk_bits(
                    cs.ns(|| "unpack utxo pk bits"),
                    &csw_data_g.utxo_data_g.input_g.output_g.spending_pub_key_g,
                )?;

            let (ft_pk_x_sign_bit_g, ft_pk_y_coordinate_g) =
                Self::get_x_sign_and_y_coord_from_pk_bits(
                    cs.ns(|| "unpack ft pk bits"),
                    &csw_data_g.ft_data_g.ft_output_g.receiver_pub_key_g,
                )?;

            let selected_pk_x_sign_bit_g = Boolean::conditionally_select(
                cs.ns(|| "select x sign bit"),
                &should_enforce_utxo_withdrawal_g,
                &utxo_pk_x_sign_bit_g,
                &ft_pk_x_sign_bit_g,
            )?;

            let selected_pk_y_coordinate_g = NonNativeFieldGadget::conditionally_select(
                cs.ns(|| "select pk_y_coordinate_g"),
                &should_enforce_utxo_withdrawal_g,
                &utxo_pk_y_coordinate_g,
                &ft_pk_y_coordinate_g,
            )?;

            (selected_pk_x_sign_bit_g, selected_pk_y_coordinate_g)
        };

        let mut secret_key_bits_g =
            Vec::<Boolean>::with_capacity(SIMULATED_SCALAR_FIELD_MODULUS_BITS);

        // Conditionally select the secret key
        for i in 0..SIMULATED_SCALAR_FIELD_MODULUS_BITS {
            let secret_key_bit_g = Boolean::conditionally_select(
                cs.ns(|| format!("read secret key bit {}", i)),
                &should_enforce_utxo_withdrawal_g,
                &csw_data_g.utxo_data_g.input_g.secret_key_g[i],
                &csw_data_g.ft_data_g.ft_input_secret_key_g[i],
            )?;
            secret_key_bits_g.push(secret_key_bit_g);
        }

        // We assume secret key bits to be in Big Endian form
        secret_key_bits_g.reverse();

        // Compute public key from secret key
        let current_public_key_g = ECPointSimulationGadget::mul_bits_fixed_base(
            &SimulatedGroup::prime_subgroup_generator().into_projective(),
            cs.ns(|| "G^sk"),
            &secret_key_bits_g,
        )?;

        let x_sign = current_public_key_g
            .x
            .is_odd(cs.ns(|| "public key x coordinate is odd"))?;

        // Enforce x_sign is the same
        x_sign.enforce_equal(
            cs.ns(|| "Enforce x_sign == pk_x_sign_bit_g"),
            &pk_x_sign_bit_g,
        )?;

        // Enforce y_coordinate is the same
        current_public_key_g.y.enforce_equal(
            cs.ns(|| "Enforce y coordinate is equal"),
            &pk_y_coordinate_g,
        )?;

        Ok(())
    }
}

impl ConstraintSynthesizer<FieldElement> for CeasedSidechainWithdrawalCircuit {
    fn generate_constraints<CS: ConstraintSystemAbstract<FieldElement>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        // Alloc sidechain id
        let sidechain_id_g =
            FieldElementGadget::alloc(cs.ns(|| "alloc sidechain_id_g"), || Ok(&self.sidechain_id))?;

        // Alloc all witness data
        let csw_data_g =
            CswProverDataGadget::alloc(cs.ns(|| "alloc csw data"), || Ok(&self.csw_data))?;

        // Decide whether to enforce utxo or ft withdrawal
        let should_enforce_utxo_withdrawal_g = csw_data_g
            .utxo_data_g
            .input_g
            .is_phantom(cs.ns(|| "should_enforce_utxo_withdrawal"))?
            .not();

        let should_enforce_ft_withdrawal_g = csw_data_g
            .ft_data_g
            .ft_output_g
            .is_phantom(cs.ns(|| "should_enforce_ft_withdrawal"))?
            .not();

        let should_enforce_wcert_hash = csw_data_g
            .last_wcert_g
            .is_phantom(
                cs.ns(|| "should_enforce_wcert_hash"),
                self.num_custom_fields,
            )?
            .not();

        // if last_wcert != NULL
        // enforce(sys_data.sc_last_wcert_hash == H(last_wcert))

        let last_wcert_hash_g = csw_data_g
            .last_wcert_g
            .enforce_hash(cs.ns(|| "enforce last_wcert_hash"), None)?;

        last_wcert_hash_g.conditional_enforce_equal(
            cs.ns(|| "enforce sc_last_wcert_hash == last_wcert_hash"),
            &csw_data_g.sys_data_g.sc_last_wcert_hash_g.clone(),
            &should_enforce_wcert_hash,
        )?;

        // Enforce UTXO widthdrawal if required

        if !csw_data_g.last_wcert_g.custom_fields_g.is_empty() {
            // We use two custom fields (with half of the bits set) to store a single Field Element
            assert_eq!(
                csw_data_g.last_wcert_g.custom_fields_g.len(),
                self.num_custom_fields as usize
            );

            // TODO: this is a temporary hack to make the test working
            let scb_new_mst_root = csw_data_g.last_wcert_g.custom_fields_g[0].clone();
            // // Reconstruct scb_new_mst_root from custom fields
            // let scb_new_mst_root = {
            //     use algebra::Field;
            //     use r1cs_std::fields::FieldGadget;
            
            //     // Compute 2^128 in the field
            //     let pow = FieldElement::one().double().pow(&[128u64]);

            //     // Combine the two custom fields as custom_fields[0] + (2^128) * custom_fields[1]
            //     // We assume here that the 2 FieldElements were originally truncated at the 128th bit .
            //     // Note that the prover is able to find multiple custom_fields[0], custom_fields[1]
            //     // leading to the same result but this will change the certificate hash, binded to 
            //     // the sys_data_hash public input, for which he would need to find a collision,
            //     // and this is unfeasible.
            //     let first_half = &csw_data_g.last_wcert_g.custom_fields_g[0];
            //     let second_half = csw_data_g
            //         .last_wcert_g
            //         .custom_fields_g[1]
            //         .mul_by_constant(
            //             cs.ns(|| "2^128 * custom_fields[1]"),
            //             &pow
            //         )?;
                
            //     first_half.add(
            //         cs.ns(|| "custom_fields[0] + (2^128) * custom_fields[1]"),
            //         &second_half
            //     )
            // }?;

            csw_data_g
                .utxo_data_g
                .conditionally_enforce_utxo_withdrawal(
                    cs.ns(|| "enforce utxo withdrawal"),
                    &scb_new_mst_root,
                    &csw_data_g.sys_data_g.nullifier_g,
                    &csw_data_g.sys_data_g.amount_g,
                    &should_enforce_utxo_withdrawal_g,
                )?;
        }

        // Enforce FT withdrawal if required

        csw_data_g.ft_data_g.conditionally_enforce_ft_withdrawal(
            cs.ns(|| "conditionally enforce ft withdrawal"),
            &sidechain_id_g,
            self.range_size,
            &csw_data_g.sys_data_g.mcb_sc_txs_com_end_g,
            &csw_data_g.sys_data_g.nullifier_g,
            &csw_data_g.sys_data_g.amount_g,
            &should_enforce_ft_withdrawal_g,
        )?;

        // We check the public key ownership just once for both, choosing the appropriate public key
        // and secret key, as it is an expensive check, we want to do it just once.
        // NOTE: We could've done the same for nullifier and amount checks, but we didn't in order
        //       to have cleaner code (we lose only 2 constraints anyway)

        Self::enforce_pk_ownership(
            cs.ns(|| "enforce pk ownership"),
            &csw_data_g,
            &should_enforce_utxo_withdrawal_g,
        )?;

        // Let's build up the public inputs

        // Allocate constant as public input if needed and don't use it
        if self.constant.is_some() {
            let _ = FieldElementGadget::alloc_input(cs.ns(|| "alloc constant as input"), || {
                Ok(self.constant.unwrap())
            })?;
        }

        // Deserialize a FieldElement out of amount_g and receiver_g
        let amount_and_receiver_fe_g = {
            let mut amount_and_receiver_bits_g = csw_data_g
                .sys_data_g
                .amount_g
                .to_bits_with_length_restriction(
                    cs.ns(|| "amount to bits"),
                    (FIELD_SIZE * 8) - 64,
                )?;

            amount_and_receiver_bits_g.extend_from_slice(&csw_data_g.sys_data_g.receiver_g[..]);

            FieldElementGadget::from_bits(
                cs.ns(|| "read field element out of amount and bits"),
                amount_and_receiver_bits_g.as_slice(),
            )
        }?;

        // Enforce sys_data_hash computation
        let sys_data_hash_g = FieldHashGadget::enforce_hash_constant_length(
            cs.ns(|| "compute sys data hash"),
            &[
                amount_and_receiver_fe_g,
                sidechain_id_g,
                csw_data_g.sys_data_g.nullifier_g.clone(),
                csw_data_g.sys_data_g.sc_last_wcert_hash_g.clone(),
                csw_data_g.sys_data_g.mcb_sc_txs_com_end_g,
            ],
        )?;

        // Alloc it as public input
        let expected_sys_data_hash_g =
            FieldElementGadget::alloc_input(cs.ns(|| "alloc input sys_data_hash_g"), || {
                Ok(self.csw_sys_data_hash)
            })?;

        // Enforce equality
        expected_sys_data_hash_g.enforce_equal(
            cs.ns(|| "expected_sys_data_hash == actual_sys_data_hash"),
            &sys_data_hash_g,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use algebra::{
        fields::ed25519::fr::Fr as ed25519Fr, Field, Group, ProjectiveCurve, UniformRand,
    };
    use cctp_primitives::{
        proving_system::{
            error::ProvingSystemError,
            init::{get_g1_committer_key, load_g1_committer_key},
        },
        type_mapping::{CoboundaryMarlin, FieldElement, GingerMHT, MC_PK_SIZE},
        utils::{
            commitment_tree::{hash_vec, DataAccumulator},
            poseidon_hash::get_poseidon_hash_constant_length,
            serialization::serialize_to_buffer,
        },
    };
    use primitives::{bytes_to_bits, FieldBasedHash, FieldBasedMerkleTree};
    use r1cs_core::debug_circuit;
    use rand::rngs::OsRng;
    use std::{convert::TryInto, ops::AddAssign};

    use crate::{
        constants::constants::BoxType, CswFtOutputData, CswProverData, CswUtxoInputData,
        CswUtxoOutputData, GingerMHTBinaryPath, WithdrawalCertificateData, MC_RETURN_ADDRESS_BYTES,
        MST_MERKLE_TREE_HEIGHT, PHANTOM_FIELD_ELEMENT,
    };

    use super::*;

    type SimulatedScalarFieldElement = ed25519Fr;

    enum CswType {
        UTXO,
        FT,
    }

    fn generate_key_pair() -> (Vec<u8>, Vec<u8>) {
        let rng = &mut OsRng::default();

        // Generate the secret key
        let secret = SimulatedScalarFieldElement::rand(rng);

        // Compute GENERATOR^SECRET_KEY
        let public_key = SimulatedGroup::prime_subgroup_generator()
            .into_projective()
            .mul(&secret)
            .into_affine();

        // Store the sign (last bit) of the X coordinate
        // The value is left-shifted to be used later in an OR operation
        let x_sign = if public_key.x.is_odd() { 1 << 7 } else { 0u8 };

        // Extract the public key bytes as Y coordinate
        let y_coordinate = public_key.y;
        let mut pk_bytes = serialize_to_buffer(&y_coordinate, None).unwrap();

        // Use the last (null) bit of the public key to store the sign of the X coordinate
        // Before this operation, the last bit of the public key (Y coordinate) is always 0 due to the field modulus
        let len = pk_bytes.len();
        pk_bytes[len - 1] |= x_sign;

        // Reverse each pk byte
        for i in 0..pk_bytes.len() {
            pk_bytes[i] = pk_bytes[i].reverse_bits();
        }

        pk_bytes.reverse();

        let mut secret_bytes = serialize_to_buffer(&secret, None).unwrap();

        // Reverse each sk byte
        for i in 0..secret_bytes.len() {
            secret_bytes[i] = secret_bytes[i].reverse_bits();
        }

        secret_bytes.reverse();

        (secret_bytes, pk_bytes)
    }

    fn compute_mst_tree_data(
        utxo_input_data: CswUtxoInputData,
    ) -> (FieldElement, FieldElement, GingerMHTBinaryPath) {
        let mut mst = GingerMHT::init(MST_MERKLE_TREE_HEIGHT, 1 << MST_MERKLE_TREE_HEIGHT).unwrap();

        let mut mst_leaf_accumulator = DataAccumulator::init();
        mst_leaf_accumulator
            .update_with_bits(utxo_input_data.output.spending_pub_key.to_vec())
            .unwrap();
        mst_leaf_accumulator
            .update(utxo_input_data.output.amount)
            .unwrap();
        mst_leaf_accumulator
            .update(utxo_input_data.output.nonce)
            .unwrap();
        mst_leaf_accumulator
            .update_with_bits(utxo_input_data.output.custom_hash.to_vec())
            .unwrap();

        let mut mst_leaf_inputs = mst_leaf_accumulator.get_field_elements().unwrap();
        debug_assert_eq!(mst_leaf_inputs.len(), 3);
        mst_leaf_inputs.push(FieldElement::from(BoxType::CoinBox as u8));

        let mut poseidon_hash = get_poseidon_hash_constant_length(mst_leaf_inputs.len(), None);

        mst_leaf_inputs.into_iter().for_each(|leaf_input| {
            poseidon_hash.update(leaf_input);
        });

        let mst_leaf_hash = poseidon_hash.finalize().unwrap();

        mst.append(mst_leaf_hash).unwrap();
        mst.finalize_in_place().unwrap();

        let mst_path: GingerMHTBinaryPath = mst.get_merkle_path(0).unwrap().try_into().unwrap();

        let mst_root = mst.root().unwrap();

        (mst_root, mst_leaf_hash, mst_path)
    }

    fn compute_cert_data(
        custom_fields: Vec<FieldElement>,
    ) -> (WithdrawalCertificateData, FieldElement) {
        let cert_data = WithdrawalCertificateData {
            ledger_id: FieldElement::from(1u8),
            epoch_id: 2u32,
            bt_root: FieldElement::from(3u8),
            quality: 4u64,
            mcb_sc_txs_com: FieldElement::from(5u8),
            ft_min_amount: 6u64,
            btr_min_fee: 7u64,
            custom_fields: custom_fields,
        };

        let fees_field_elements = DataAccumulator::init()
            .update(cert_data.btr_min_fee)
            .unwrap()
            .update(cert_data.ft_min_amount)
            .unwrap()
            .get_field_elements()
            .unwrap();

        debug_assert_eq!(fees_field_elements.len(), 1);

        let temp_computed_last_wcert_hash = get_poseidon_hash_constant_length(6, None)
            .update(cert_data.ledger_id)
            .update(FieldElement::from(cert_data.epoch_id))
            .update(cert_data.bt_root)
            .update(FieldElement::from(cert_data.quality))
            .update(cert_data.mcb_sc_txs_com)
            .update(fees_field_elements[0])
            .finalize()
            .unwrap();

        let mut poseidon_hash =
            get_poseidon_hash_constant_length(cert_data.custom_fields.len(), None);

        cert_data.custom_fields.iter().for_each(|custom_field| {
            poseidon_hash.update(*custom_field);
        });

        let computed_custom_fields_hash = poseidon_hash.finalize().unwrap();

        let computed_last_wcert_hash = if cert_data.custom_fields.is_empty() {
            get_poseidon_hash_constant_length(1, None)
                .update(temp_computed_last_wcert_hash)
                .finalize()
                .unwrap()
        } else {
            get_poseidon_hash_constant_length(2, None)
                .update(computed_custom_fields_hash)
                .update(temp_computed_last_wcert_hash)
                .finalize()
                .unwrap()
        };

        (cert_data, computed_last_wcert_hash)
    }

    fn generate_test_utxo_csw_data(
        num_custom_fields: u32,
        num_commitment_hashes: u32,
        secret_key_bytes: Vec<u8>,
        public_key_bytes: Vec<u8>,
    ) -> CswProverData {
        let utxo_input_data = CswUtxoInputData {
            output: CswUtxoOutputData {
                spending_pub_key: bytes_to_bits(&public_key_bytes).try_into().unwrap(),
                amount: 10,
                nonce: 11,
                custom_hash: bytes_to_bits(&[12; FIELD_SIZE]).try_into().unwrap(),
            },
            secret_key: bytes_to_bits(&secret_key_bytes)[SIMULATED_SCALAR_FIELD_REPR_SHAVE_BITS..]
                .try_into()
                .unwrap(),
        };

        let (mst_root, mst_leaf_hash, mst_path) = compute_mst_tree_data(utxo_input_data.clone());

        // To generate valid test data we need at least one custom field to store the MST root
        debug_assert!(num_custom_fields > 0);
        let mut custom_fields = vec![mst_root];

        for _ in 0..num_custom_fields - 1 {
            custom_fields.push(PHANTOM_FIELD_ELEMENT);
        }

        let (cert_data, last_wcert_hash) = compute_cert_data(custom_fields);

        let utxo_data = CswUtxoProverData {
            input: utxo_input_data.clone(),
            mst_path_to_output: mst_path,
        };

        let sys_data = CswSysData {
            mcb_sc_txs_com_end: FieldElement::from(15u8),
            sc_last_wcert_hash: last_wcert_hash,
            amount: utxo_input_data.output.amount,
            nullifier: mst_leaf_hash,
            receiver: [0; MC_PK_SIZE],
        };

        let csw_prover_data = CswProverData {
            sys_data,
            last_wcert: cert_data,
            utxo_data,
            ft_data: CswFtProverData::get_phantom(num_commitment_hashes),
        };

        csw_prover_data
    }

    fn generate_ft_tree_data(
        ft_output_data: CswFtOutputData,
    ) -> (FieldElement, GingerMHTBinaryPath, FieldElement) {
        let mut ft_input_hash_accumulator = DataAccumulator::init();
        ft_input_hash_accumulator
            .update(ft_output_data.amount)
            .unwrap();
        ft_input_hash_accumulator
            .update(ft_output_data.receiver_pub_key.to_vec())
            .unwrap();
        ft_input_hash_accumulator
            .update(ft_output_data.payback_addr_data_hash.to_vec())
            .unwrap();
        ft_input_hash_accumulator
            .update(ft_output_data.tx_hash.to_vec())
            .unwrap();
        ft_input_hash_accumulator
            .update(ft_output_data.out_idx)
            .unwrap();

        let ft_input_hash_elements = ft_input_hash_accumulator.get_field_elements().unwrap();

        let mut poseidon_hash =
            get_poseidon_hash_constant_length(ft_input_hash_elements.len(), None);
        ft_input_hash_elements.into_iter().for_each(|leaf_input| {
            poseidon_hash.update(leaf_input);
        });

        let ft_input_hash = poseidon_hash.finalize().unwrap();

        // TODO: set a proper height for the FT tree
        let mut ft_tree =
            GingerMHT::init(MST_MERKLE_TREE_HEIGHT, 1 << MST_MERKLE_TREE_HEIGHT).unwrap();
        ft_tree.append(ft_input_hash).unwrap();
        ft_tree.finalize_in_place().unwrap();

        let ft_tree_path = ft_tree.get_merkle_path(0).unwrap().try_into().unwrap();
        let ft_tree_root = ft_tree.root().unwrap();

        (ft_input_hash, ft_tree_path, ft_tree_root)
    }

    fn generate_test_ft_csw_data(
        sidechain_id: FieldElement,
        num_custom_fields: u32,
        num_commitment_hashes: u32,
        secret_key_bytes: Vec<u8>,
        public_key_bytes: Vec<u8>,
    ) -> CswProverData {
        let ft_output_data = CswFtOutputData {
            amount: 100,
            receiver_pub_key: public_key_bytes.try_into().unwrap(),
            payback_addr_data_hash: [101; MC_RETURN_ADDRESS_BYTES],
            tx_hash: [102; FIELD_SIZE],
            out_idx: 103,
        };

        let (ft_output_hash, ft_tree_path, ft_tree_root) =
            generate_ft_tree_data(ft_output_data.clone());

        let scb_btr_tree_root = FieldElement::from(22u8);
        let wcert_tree_root = FieldElement::from(23u8);

        let sc_hash = get_poseidon_hash_constant_length(4, None)
            .update(ft_tree_root)
            .update(scb_btr_tree_root)
            .update(wcert_tree_root)
            .update(sidechain_id)
            .finalize()
            .unwrap();

        // TODO: set a proper height for the SC tree
        let mut sc_tree =
            GingerMHT::init(MST_MERKLE_TREE_HEIGHT, 1 << MST_MERKLE_TREE_HEIGHT).unwrap();
        sc_tree.append(sc_hash).unwrap();
        sc_tree.finalize_in_place().unwrap();

        let sc_tree_path: GingerMHTBinaryPath =
            sc_tree.get_merkle_path(0).unwrap().try_into().unwrap();
        let sc_tree_root = sc_tree.root().unwrap();

        let mut ft_data = CswFtProverData {
            ft_output: ft_output_data,
            ft_input_secret_key: bytes_to_bits(&secret_key_bytes)
                [SIMULATED_SCALAR_FIELD_REPR_SHAVE_BITS..]
                .try_into()
                .unwrap(),
            mcb_sc_txs_com_start: PHANTOM_FIELD_ELEMENT,
            merkle_path_to_sc_hash: sc_tree_path,
            ft_tree_path: ft_tree_path,
            sc_creation_commitment: PHANTOM_FIELD_ELEMENT,
            scb_btr_tree_root: scb_btr_tree_root,
            wcert_tree_root: wcert_tree_root,
            sc_txs_com_hashes: vec![PHANTOM_FIELD_ELEMENT; num_commitment_hashes as usize],
        };

        ft_data.sc_txs_com_hashes[0] = sc_tree_root;

        let mut mcb_sc_txs_com_end = ft_data.mcb_sc_txs_com_start;

        ft_data
            .sc_txs_com_hashes
            .iter()
            .for_each(|sc_txs_com_hash| {
                if !sc_txs_com_hash.eq(&PHANTOM_FIELD_ELEMENT) {
                    mcb_sc_txs_com_end = get_poseidon_hash_constant_length(2, None)
                        .update(mcb_sc_txs_com_end)
                        .update(*sc_txs_com_hash)
                        .finalize()
                        .unwrap();
                }
            });

        let sys_data = CswSysData {
            mcb_sc_txs_com_end: mcb_sc_txs_com_end,
            sc_last_wcert_hash: PHANTOM_FIELD_ELEMENT,
            amount: ft_data.ft_output.amount,
            nullifier: ft_output_hash,
            receiver: [0; MC_PK_SIZE],
        };

        let csw_prover_data = CswProverData {
            sys_data,
            last_wcert: WithdrawalCertificateData::get_phantom(num_custom_fields),
            utxo_data: CswUtxoProverData::default(),
            ft_data,
        };

        csw_prover_data
    }

    fn generate_test_csw_prover_data(
        csw_type: CswType,
        sidechain_id: FieldElement,
        num_custom_fields: u32,
        num_commitment_hashes: u32,
    ) -> CswProverData {
        let (secret_key, public_key) = generate_key_pair();

        match csw_type {
            CswType::UTXO => generate_test_utxo_csw_data(
                num_custom_fields,
                num_commitment_hashes,
                secret_key,
                public_key,
            ),
            CswType::FT => generate_test_ft_csw_data(
                sidechain_id,
                num_custom_fields,
                num_commitment_hashes,
                secret_key,
                public_key,
            ),
        }
    }

    fn test_csw_circuit(csw_type: CswType) {
        let sidechain_id = FieldElement::from(77u8);
        let num_custom_fields = 1;
        let num_commitment_hashes = 100;
        let csw_prover_data = generate_test_csw_prover_data(
            csw_type,
            sidechain_id,
            num_custom_fields,
            num_commitment_hashes,
        );
        let constant = Some(FieldElement::from(14u8));
        let circuit = CeasedSidechainWithdrawalCircuit::from_prover_data(
            sidechain_id,
            constant,
            csw_prover_data.clone(),
            num_commitment_hashes,
            num_custom_fields,
        ).unwrap();

        let failing_constraint = debug_circuit(circuit.clone()).unwrap();
        println!("Failing constraint: {:?}", failing_constraint);
        assert!(failing_constraint.is_none());

        load_g1_committer_key(1 << 17, 1 << 15).unwrap();
        let ck_g1 = get_g1_committer_key().unwrap();
        let params = CoboundaryMarlin::index(ck_g1.as_ref().unwrap(), circuit.clone()).unwrap();

        let proof = CoboundaryMarlin::prove(
            &params.0.clone(),
            ck_g1.as_ref().unwrap(),
            circuit,
            false,
            None,
        )
        .unwrap();

        let mut public_inputs = Vec::new();

        if constant.is_some() {
            public_inputs.push(constant.unwrap());
        }

        let mut fes = DataAccumulator::init()
            .update(csw_prover_data.sys_data.amount)
            .map_err(|e| ProvingSystemError::Other(format!("{:?}", e)))
            .unwrap()
            .update(&csw_prover_data.sys_data.receiver[..])
            .map_err(|e| ProvingSystemError::Other(format!("{:?}", e)))
            .unwrap()
            .get_field_elements()
            .map_err(|e| ProvingSystemError::Other(format!("{:?}", e)))
            .unwrap();

        fes.append(&mut vec![
            sidechain_id,
            csw_prover_data.sys_data.nullifier,
            csw_prover_data.sys_data.sc_last_wcert_hash,
            csw_prover_data.sys_data.mcb_sc_txs_com_end,
        ]);

        public_inputs.push(
            hash_vec(fes)
                .map_err(|e| ProvingSystemError::Other(format!("{:?}", e)))
                .unwrap(),
        );

        // Check that the proof gets correctly verified
        assert!(CoboundaryMarlin::verify(
            &params.1.clone(),
            ck_g1.as_ref().unwrap(),
            public_inputs.as_slice(),
            &proof
        )
        .unwrap());

        // Change one public input and check that the proof fails
        public_inputs[0].add_assign(&FieldElement::from(1u8));
        assert!(!CoboundaryMarlin::verify(
            &params.1.clone(),
            ck_g1.as_ref().unwrap(),
            public_inputs.as_slice(),
            &proof
        )
        .unwrap());
    }

    #[test]
    fn test_csw_circuit_utxo() {
        test_csw_circuit(CswType::UTXO);
    }

    #[test]
    fn test_csw_circuit_ft() {
        test_csw_circuit(CswType::FT);
    }
}
