/*++

Licensed under the Apache-2.0 license.

File Name:

    rt_alias.rs

Abstract:

    Crypto helper routines

--*/
use crate::flow::crypto::Crypto;
use crate::flow::dice::{DiceInput, DiceLayer, DiceOutput};
use crate::flow::pcr::{extend_pcr0, extend_pcr1};
use crate::flow::x509::X509;
use crate::fmc_env::FmcEnv;
use crate::HandOff;
use caliptra_common::cprintln;
use caliptra_common::crypto::Ecc384KeyPair;
use caliptra_drivers::{
    Array4x12, CaliptraResult, Ecc384PubKey, Hmac384Data, Hmac384Key, KeyId, KeyReadArgs,
};

#[derive(Default)]
pub struct RtAliasLayer {}

impl DiceLayer for RtAliasLayer {
    /// Perform derivations for the DICE layer
    fn derive(env: &FmcEnv, input: &DiceInput) -> CaliptraResult<DiceOutput> {
        // At this point PCR0 & PCR1 must have the same value. We use the value
        // of PCR1 as the UDS for deriving the CDI
        let uds = env
            .pcr_bank()
            .map(|p| p.read_pcr(caliptra_drivers::PcrId::PcrId1));

        // Derive the Rt layer CDI.
        let cdi = Self::derive_cdi(env, uds, input.cdi)?;

        // Derive DICE Key Pair from CDI
        let key_pair = Self::derive_key_pair(env, cdi, input.subj_priv_key)?;

        // Generate the Subject Serial Number and Subject Key Identifier.
        //
        // This information will be used by next DICE Layer while generating
        // certificates
        let subj_sn = X509::subj_sn(env, &key_pair.pub_key)?;
        let subj_key_id = X509::subj_key_id(env, &key_pair.pub_key)?;

        let output = input.to_output(key_pair, subj_sn, subj_key_id);

        // Generate Local Device ID Certificate
        Self::generate_cert_sig(env, input, &output)?;

        // Generate the output for next layer

        Ok(output)
        //Err(0xdead)
    }
}

impl RtAliasLayer {
    #[inline(never)]
    pub fn run(env: &FmcEnv, hand_off: &HandOff) -> CaliptraResult<()> {
        cprintln!("[art] Extend PCRs");
        Self::extend_pcrs(env, hand_off)?;
        if let Ok(input) = Self::dice_input_from_hand_off(env, hand_off) {
            let output = Self::derive(env, &input).unwrap_or_else(|_| crate::report_error(0xdead));
        }
        Ok(())
    }

    pub fn dice_input_from_hand_off(env: &FmcEnv, hand_off: &HandOff) -> CaliptraResult<DiceInput> {
        // Create initial output
        let input = DiceInput {
            cdi: hand_off.fmc_cdi(),
            subj_priv_key: hand_off.fmc_priv_key(),
            auth_key_pair: Ecc384KeyPair {
                priv_key: KeyId::KeyId5,
                pub_key: Ecc384PubKey::default(),
            },
            auth_sn: [0u8; 64],
            auth_key_id: [0u8; 20],
            uds_key: hand_off.fmc_cdi(),
        };

        Ok(input)
    }

    /// Derive Composite Device Identity (CDI) from Unique Device Secret (UDS)
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    /// * `uds` - Array containing the UDS
    /// * `cdi` - Key Slot to store the generated CDI
    ///
    /// # Returns
    ///
    /// * `KeyId` - KeySlot containing the DICE CDI
    fn derive_cdi(env: &FmcEnv, uds: Array4x12, cdi: KeyId) -> CaliptraResult<KeyId> {
        // CDI Key
        let key = Hmac384Key::Key(KeyReadArgs::new(cdi));
        let data: [u8; 48] = uds.into();
        let data = Hmac384Data::Slice(&data);
        let cdi = Crypto::hmac384_mac(env, key, data, cdi)?;
        Ok(cdi)
    }

    /// Derive Dice Layer Key Pair
    ///
    /// # Arguments
    ///
    /// * `env`      - Fmc Environment
    /// * `cdi`      - Composite Device Identity
    /// * `priv_key` - Key slot to store the private key into
    ///
    /// # Returns
    ///
    /// * `Ecc384KeyPair` - Derive DICE Layer Key Pair
    fn derive_key_pair(env: &FmcEnv, cdi: KeyId, priv_key: KeyId) -> CaliptraResult<Ecc384KeyPair> {
        Crypto::ecc384_key_gen(env, cdi, priv_key)
    }

    /// Extend the PCR0 & PCR1
    ///
    /// PCR0 is a journey PCR and is locked for clear on cold boot. PCR1
    /// is the current PCR and is cleared on any reset
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    pub fn extend_pcrs(env: &FmcEnv, hand_off: &HandOff) -> CaliptraResult<()> {
        extend_pcr0(env, hand_off)?;
        extend_pcr1(env, hand_off)?;
        Ok(())
    }

    /// Generate Local Device ID Certificate Signature
    ///
    /// # Arguments
    ///
    /// * `env`    - ROM Environment
    /// * `input`  - DICE Input
    /// * `output` - DICE Output
    fn generate_cert_sig(
        env: &FmcEnv,
        input: &DiceInput,
        output: &DiceOutput,
    ) -> CaliptraResult<()> {
        let _auth_priv_key = input.auth_key_pair.priv_key;
        let _auth_pub_key = &input.auth_key_pair.pub_key;
        let _pub_key = &output.subj_key_pair.pub_key;

        // Certificate `To Be Signed` Parameters
        //let params = RtAliasCertTbsParams {
        //    ueid: &X509::ueid(env)?,
        //    subject_sn: &output.subj_sn,
        //    subject_key_id: &output.subj_key_id,
        //    issuer_sn: &input.auth_sn,
        //    authority_key_id: &input.auth_key_id,
        //    serial_number: &X509::cert_sn(env, pub_key)?,
        //   public_key: &pub_key.to_der(),
        //    tcb_info_rt_tci: &env.data_vault().map(|d| d.fmc_tci()).into(),
        //   tcb_info_owner_pk_hash: &env.data_vault().map(|d| d.owner_pk_hash()).into(),
        //};

        // Generate the `To Be Signed` portion of the CSR
        //let tbs = RtAliasCertTbs::new(&params);

        // Sign the the `To Be Signed` portion
        //cprintln!(
        //    "[afmc] Signing Cert with AUTHORITY.KEYID = {}",
        //    auth_priv_key as u8
        //);
        //let sig = Crypto::ecdsa384_sign(env, auth_priv_key, tbs.tbs())?;

        // Clear the authority private key
        //cprintln!("[afmc] Erasing AUTHORITY.KEYID = {}", auth_priv_key as u8);
        //env.key_vault().map(|k| k.erase_key(auth_priv_key))?;

        // Verify the signature of the `To Be Signed` portion
        //if !Crypto::ecdsa384_verify(env, auth_pub_key, tbs.tbs(), &sig)? {
        //    raise_err!(CertVerify);
        //}

        //let _pub_x: [u8; 48] = pub_key.x.into();
        //let _pub_y: [u8; 48] = pub_key.y.into();
        //cprint_slice!("[art] PUB.X", _pub_x);
        //cprint_slice!("[art] PUB.Y", _pub_y);

        //let _sig_r: [u8; 48] = sig.r.into();
        //let _sig_s: [u8; 48] = sig.s.into();
        //cprint_slice!("[art] SIG.R", _sig_r);
        //cprint_slice!("[art] SIG.S", _sig_s);

        // Lock the FMC Certificate Signature in data vault until next boot
        //        env.data_vault().map(|d| d.set_fmc_dice_signature(&sig));

        // Lock the FMC Public key in the data vault until next boot
        //        env.data_vault().map(|d| d.set_fmc_pub_key(pub_key));

        Ok(())
    }
}
