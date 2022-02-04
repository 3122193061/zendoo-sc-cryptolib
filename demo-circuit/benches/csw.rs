use std::convert::TryInto;

use algebra::*;
use criterion::{Criterion, criterion_group, criterion_main, BatchSize};
use demo_circuit::*;
use primitives::*;
use cctp_primitives::{commitment_tree::hashers::*, proving_system::init::{load_g1_committer_key, get_g1_committer_key}, utils::get_bt_merkle_root};
use rand::{thread_rng, Rng};

fn get_test_key_pair() -> (
    [u8; SC_PUBLIC_KEY_LENGTH],
    [bool; SIMULATED_SCALAR_FIELD_MODULUS_BITS],
) {
    let test_sc_secrets = vec![
        "50d5e4c0b15402013941a3c525c6af85e7ab8a2da39a59707211ddd53def965e",
        "70057ef1805240ab9bf2772c0e25a3b57c5911e7dca4120f8e265d750ed77346",
        "1089ba2f1bee0bbc8f2270541bb22595026fe7d828033845d5ed82f31386b65d",
        "305510ff60436930d09ccb8e2321211967aadfe904f30ccb13f600786f9e297a",
        "c80155e642065ca1cc575f69fa658f837b880df76771a335f40ce27240735443",
        "50e8a8b680918c1840bedfa1650e53f94c8823e81f6efd24d9e37fedfab9344f",
        "98b4a1c05a44708014a895d27923c7c20f3260e1bc9f2d5edcd6996e4d017944",
        "b840b87072d095849d433ec11ddd49b138f1823dae16268dcbe46d8035635e74",
        "b07b2199ad9258449889686423a3c9382cf428355ac348bce40c9d639edf6759",
        "302fcad55ae4b8f54ab3ab01eaf171873d38676075dff601e4b12a377c7c217d",
        "001d2489d7b8caab450822ee6393d0b9324da8af67fda2b2cba19b46f64de852",
        "3811067e9f19d35b2f7487eeb08076a9c4a459dec10791095ebae03bb613f375",
    ];

    let test_sc_te_public_keys = vec![
        "f165e1e5f7c290e52f2edef3fbab60cbae74bfd3274f8e5ee1de3345c954a166",
        "8f80338eef733ec67c601349c4a8251393b28deb722cfd0a91907744a26d3dab",
        "cc1983469486418cd66dcdc8664677c263487b736840cfd1532e144386fa7610",
        "88166617f91bc145b243c2ae6e1088f1208bf17311cca74dbf032fee25b219e0",
        "6f97404947a00311785785217b1759b002cbae16da26e0801f0dcbe4e00d5f45",
        "fb7a8589cbe59427b2e9c91a5091bf43cf2080f1d4f1947af0d214ca825076f0",
        "30da57cda802def8dfd764812f2e3c82eb2871b2a14e3bb634f2195ef733796d",
        "622c8cb09b558fecfc60ce1ec4b1e3014fe04f4628e06cad58ce9ded4d192a2d",
        "3733056f59780d2f17adf073582634940c6ae57d530345d28e9b6b7cf1d3dcfb",
        "423cb2cdd87b3e612517cf77e68d918914b0705d8937ef7e25b24a53620bc9d1",
        "f5206f3569998819efc57e83e8521110e9414c8dca8c5e96c173366e9acd958f",
        "f1785d4d2f6017ad7a25f795db5beb48d38d6f8cd44dcc3b7f321b8e2a5352fd",
    ];

    let rng = &mut thread_rng();
    let random_idx = rng.gen_range(0..test_sc_secrets.len());

    let (test_sc_secret, test_sc_public_key) = (
        test_sc_secrets[random_idx],
        test_sc_te_public_keys[random_idx],
    );

    // Parse pk LE bits
    let pk_bytes = hex::decode(test_sc_public_key).unwrap();

    // Parse sk LE bits
    let sk_bytes = hex::decode(test_sc_secret).unwrap();
    let sk = deserialize_fe_unchecked(sk_bytes.to_vec());

    // Convert it to bits and reverse them (circuit expects them in LE but write_bits outputs in BE)
    let mut sk_bits = sk.write_bits();
    sk_bits.reverse();

    (pk_bytes.try_into().unwrap(), sk_bits.try_into().unwrap())
}

fn compute_mst_tree_data(
    utxo_output_data: CswUtxoOutputData,
) -> (FieldElement, FieldElement, GingerMHTBinaryPath) {
    let mut mst = GingerMHT::init(MST_MERKLE_TREE_HEIGHT, 1 << MST_MERKLE_TREE_HEIGHT).unwrap();

    let mst_leaf_hash = utxo_output_data
        .hash(Some(&[FieldElement::from(BoxType::CoinBox as u8)]))
        .unwrap();

    mst.append(mst_leaf_hash).unwrap();
    mst.finalize_in_place().unwrap();

    let mst_path: GingerMHTBinaryPath = mst.get_merkle_path(0).unwrap().try_into().unwrap();

    let mst_root = mst.root().unwrap();

    (mst_root, mst_leaf_hash, mst_path)
}

fn compute_cert_data(
    custom_fields: Vec<FieldElement>,
) -> (WithdrawalCertificateData, FieldElement) {
    let rng = &mut thread_rng();
    let cert_data = WithdrawalCertificateData {
        ledger_id: FieldElement::rand(rng),
        epoch_id: rng.gen(),
        bt_root: get_bt_merkle_root(None).unwrap(),
        quality: rng.gen(),
        mcb_sc_txs_com: FieldElement::rand(rng),
        ft_min_amount: rng.gen(),
        btr_min_fee: rng.gen(),
        custom_fields,
    };

    let custom_fields_ref = {
        if cert_data.custom_fields.is_empty() {
            None
        } else {
            Some(
                cert_data
                    .custom_fields
                    .iter()
                    .collect::<Vec<&FieldElement>>(),
            )
        }
    };

    let computed_last_wcert_hash = hash_cert(
        &cert_data.ledger_id,
        cert_data.epoch_id,
        cert_data.quality,
        None,
        custom_fields_ref,
        &cert_data.mcb_sc_txs_com,
        cert_data.btr_min_fee,
        cert_data.ft_min_amount,
    )
    .unwrap();

    (cert_data, computed_last_wcert_hash)
}

fn generate_test_utxo_csw_data(
    num_custom_fields: u32,
    secret_key: [bool; SIMULATED_SCALAR_FIELD_MODULUS_BITS],
    spending_pub_key: [u8; SC_PUBLIC_KEY_LENGTH],
) -> (
    CswSysData,
    WithdrawalCertificateData,
    CswUtxoProverData,
) {
    let rng = &mut thread_rng();
    let utxo_input_data = CswUtxoInputData {
        output: CswUtxoOutputData {
            spending_pub_key,
            amount: rng.gen(),
            nonce: rng.gen(),
            custom_hash: rng.gen::<[u8; FIELD_SIZE]>(),
        },
        secret_key,
    };

    let (mst_root, mst_leaf_hash, mst_path) =
        compute_mst_tree_data(utxo_input_data.output.clone());

    let custom_fields = {
        if num_custom_fields == 0 {
            vec![]
        } else {
            // To generate valid test data we need at least 2 custom field to store the MST root
            debug_assert!(num_custom_fields >= 2);

            // Split mst_root in 2

            let mut custom_fields = {
                let (mst_root_1, mst_root_2) =
                    split_field_element_at_index(&mst_root, FIELD_SIZE / 2).unwrap();
                vec![mst_root_1, mst_root_2]
            };

            for _ in 0..num_custom_fields - 2 {
                custom_fields.push(FieldElement::default());
            }

            custom_fields
        }
    };

    let (cert_data, last_wcert_hash) = compute_cert_data(custom_fields);

    let utxo_data = CswUtxoProverData {
        input: utxo_input_data.clone(),
        mst_path_to_output: mst_path,
    };

    let rng = &mut thread_rng();
    let sys_data = CswSysData::new(
        Some(FieldElement::rand(rng)),
        Some(last_wcert_hash),
        utxo_input_data.output.amount,
        mst_leaf_hash,
        rng.gen::<[u8; MC_PK_SIZE]>(),
    );

    (sys_data, cert_data, utxo_data)
}

fn generate_test_csw_prover_data(
    num_custom_fields: u32,
) -> (
    CswSysData,
    WithdrawalCertificateData,
    CswUtxoProverData,
) {
    let (public_key, secret_key) = get_test_key_pair();
    generate_test_utxo_csw_data(num_custom_fields, secret_key, public_key)
}

fn bench_csw(c: &mut Criterion) {
    let _ = load_g1_committer_key(1 << 20 - 1);
    let ck_g1 = get_g1_committer_key(Some(1 << 18 - 1)).unwrap();
    assert_eq!(ck_g1.comm_key.len(), 1 << 18);

    let num_custom_fields = 2;
    let (sys_data, last_wcert, utxo_data) = generate_test_csw_prover_data(num_custom_fields);

    // Generate circuit setup and proving instances
    let setup_circuit = CeasedSidechainWithdrawalCircuit::get_instance_for_setup(
        1,
        num_custom_fields,
        true,
    );

    let rng = &mut thread_rng();

    let sidechain_id = FieldElement::rand(rng);
    let constant = FieldElement::rand(rng);
    let circuit = CeasedSidechainWithdrawalCircuit::new(
        sidechain_id,
        Some(constant),
        sys_data.clone(),
        Some(last_wcert.clone()),
        Some(utxo_data.clone()),
        None,
        1,
        num_custom_fields,
    )
    .unwrap();

    for max_num_commitment_hashes in vec![100, 500, 1000, 2000, 3000] {

        // Generate params
        let mut new_setup_circuit = setup_circuit.clone();
        new_setup_circuit.range_size = max_num_commitment_hashes;

        let params = CoboundaryMarlin::index(&ck_g1, new_setup_circuit).unwrap();

        // Bench proof creation
        let mut new_circuit = circuit.clone();
        new_circuit.range_size = max_num_commitment_hashes;

        c.bench_function(
            format!("CSW proof creation. Num hashes = {} => Withdrawal Epoch Length = {}", max_num_commitment_hashes, (5 * max_num_commitment_hashes)/11 ).as_str(),
            |b | b.iter_batched(
                || new_circuit.clone(),
                |circuit| CoboundaryMarlin::prove(&params.0, &ck_g1, circuit, true, Some(rng)).unwrap(),
                BatchSize::PerIteration
            )
        );

        // Create proof to be used for verification
        let proof = CoboundaryMarlin::prove(&params.0, &ck_g1, new_circuit, true, Some(rng)).unwrap();

        // Bench proof verification 
        let csw_sys_data_hash =
            CeasedSidechainWithdrawalCircuit::compute_csw_sys_data_hash(
                &sys_data,
                sidechain_id,
            )
            .unwrap();
        let public_inputs = vec![constant, csw_sys_data_hash];

        c.bench_function(
            format!("CSW proof verification. Num hashes = {} => Withdrawal Epoch Length = {}", max_num_commitment_hashes, (5 * max_num_commitment_hashes)/11 ).as_str(),
            |b | b.iter(
                || assert!(CoboundaryMarlin::verify(&params.1, &ck_g1, public_inputs.as_slice(), &proof).unwrap())
            )
        );
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_csw
);
criterion_main!(benches);