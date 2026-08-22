use boxkey_core::dkg;
use boxkey_core::frost_adapter;
use proptest::prelude::*;

proptest! {
    #[test]
    fn valid_share_produces_valid_signature(
        msg_byte in any::<u8>(),
    ) {
        let (shares, _) = dkg::run_dkg(2, 2);
        let group_key = shares[0].group_public_key();
        let msg = [msg_byte; 32];

        let mut rng = rand::rngs::OsRng;
        let (h, comm) = frost_adapter::generate_nonces(&shares[0], &mut rng).unwrap();
        let (h2, comm2) = frost_adapter::generate_nonces(&shares[1], &mut rng).unwrap();

        let sig0 = frost_adapter::sign_partial(
            &shares[0], &msg, &[comm.clone(), comm2.clone()], &h,
        ).unwrap();
        let sig1 = frost_adapter::sign_partial(
            &shares[1], &msg, &[comm, comm2], &h2,
        ).unwrap();

        let agg = frost_adapter::aggregate_signatures(&[sig0, sig1], &group_key, &msg).unwrap();
        prop_assert!(frost_adapter::verify_schnorr(&agg, &group_key, &msg).is_ok());
    }

    #[test]
    fn wrong_group_key_rejects(
        msg_byte in any::<u8>(),
    ) {
        let (shares, _) = dkg::run_dkg(2, 2);
        let (other_shares, _) = dkg::run_dkg(2, 2);
        let wrong_group = other_shares[0].group_public_key();
        let group_key = shares[0].group_public_key();
        let msg = [msg_byte; 32];

        let mut rng = rand::rngs::OsRng;
        let (h, comm) = frost_adapter::generate_nonces(&shares[0], &mut rng).unwrap();
        let (h2, comm2) = frost_adapter::generate_nonces(&shares[1], &mut rng).unwrap();

        let sig0 = frost_adapter::sign_partial(
            &shares[0], &msg, &[comm.clone(), comm2.clone()], &h,
        ).unwrap();
        let sig1 = frost_adapter::sign_partial(
            &shares[1], &msg, &[comm, comm2], &h2,
        ).unwrap();

        let agg = frost_adapter::aggregate_signatures(&[sig0, sig1], &group_key, &msg).unwrap();
        prop_assert!(frost_adapter::verify_schnorr(&agg, &wrong_group, &msg).is_err(),
            "wrong group key debe fallar");
    }
}