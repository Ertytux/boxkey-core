use boxkey_core::api::{BoxKeyCore, BoxKeyCoreImpl};
use boxkey_core::error::Error;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

fn to_pyerr(e: Error) -> PyErr {
    PyValueError::new_err(e.to_string())
}

fn hash32(bytes: Vec<u8>) -> Result<[u8; 32], PyErr> {
    bytes
        .try_into()
        .map_err(|_| PyValueError::new_err("message_hash debe ser de 32 bytes"))
}

fn arr32(bytes: Vec<u8>) -> Result<[u8; 32], PyErr> {
    bytes
        .try_into()
        .map_err(|_| PyValueError::new_err("debe ser de 32 bytes"))
}

fn arr33(bytes: Vec<u8>) -> Result<[u8; 33], PyErr> {
    bytes
        .try_into()
        .map_err(|_| PyValueError::new_err("debe ser de 33 bytes"))
}

#[pyclass(name = "SecretShare")]
#[derive(Clone)]
pub struct PySecretShare(pub boxkey_core::SecretShare);

#[pyclass(name = "Commitment")]
#[derive(Clone)]
pub struct PyCommitment(pub boxkey_core::Commitment);

#[pymethods]
impl PyCommitment {
    fn to_bytes(&self) -> Vec<u8> {
        self.0 .0.clone()
    }

    #[staticmethod]
    fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(boxkey_core::Commitment(bytes))
    }
}

#[pyclass(name = "EncryptedShare")]
#[derive(Clone)]
pub struct PyEncryptedShare(pub boxkey_core::EncryptedShare);

#[pymethods]
impl PyEncryptedShare {
    #[getter]
    fn recipient(&self) -> PyPublicKey {
        PyPublicKey(self.0.recipient)
    }

    #[getter]
    fn ciphertext(&self) -> Vec<u8> {
        self.0.ciphertext.clone()
    }
}

#[pyclass(name = "Share")]
#[derive(Clone)]
pub struct PyShare(pub boxkey_core::Share);

#[pymethods]
impl PyShare {
    #[getter]
    fn identifier(&self) -> u32 {
        self.0.identifier()
    }

    #[getter]
    fn threshold(&self) -> u8 {
        self.0.threshold()
    }

    #[getter]
    fn group_public_key(&self) -> PyPublicKey {
        PyPublicKey(self.0.group_public_key())
    }

    #[getter]
    fn partial_public_key(&self) -> PyPublicKey {
        PyPublicKey(self.0.partial_public_key())
    }

    #[getter]
    fn full_public_key_point(&self) -> Vec<u8> {
        self.0.full_public_key_point().to_vec()
    }
}

#[pyclass(name = "PublicKey")]
#[derive(Clone)]
pub struct PyPublicKey(pub boxkey_core::PublicKey);

#[pymethods]
impl PyPublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    #[staticmethod]
    fn from_bytes(bytes: Vec<u8>) -> Result<Self, PyErr> {
        let b = arr32(bytes)?;
        Ok(Self(boxkey_core::PublicKey::from_bytes(b)))
    }

    fn __repr__(&self) -> String {
        format!("PublicKey({})", hex::encode(self.0.to_bytes()))
    }
}

#[pyclass(name = "SecretKey")]
#[derive(Clone)]
pub struct PySecretKey(pub boxkey_core::SecretKey);

#[pymethods]
impl PySecretKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0 .0.to_vec()
    }

    #[staticmethod]
    fn from_bytes(bytes: Vec<u8>) -> Result<Self, PyErr> {
        let b = arr32(bytes)?;
        Ok(Self(boxkey_core::SecretKey(b)))
    }

    fn __repr__(&self) -> String {
        "SecretKey([REDACTED])".to_string()
    }
}

#[pyclass(name = "PartialSignature")]
#[derive(Clone)]
pub struct PyPartialSignature(pub boxkey_core::PartialSignature);

#[pymethods]
impl PyPartialSignature {
    fn to_bytes(&self) -> Vec<u8> {
        self.0 .0.to_vec()
    }

    fn identifier(&self) -> u32 {
        self.0.identifier()
    }

    #[staticmethod]
    fn from_bytes(bytes: Vec<u8>) -> Self {
        let mut arr = [0u8; 36];
        let n = bytes.len().min(36);
        arr[..n].copy_from_slice(&bytes[..n]);
        Self(boxkey_core::PartialSignature(arr))
    }
}

#[pyclass(name = "SchnorrSignature")]
#[derive(Clone)]
pub struct PySchnorrSignature(pub boxkey_core::SchnorrSignature);

#[pymethods]
impl PySchnorrSignature {
    fn to_bytes(&self) -> Vec<u8> {
        self.0 .0.to_vec()
    }

    #[staticmethod]
    fn from_bytes(bytes: Vec<u8>) -> Result<Self, PyErr> {
        let b: [u8; 64] = bytes
            .try_into()
            .map_err(|_| PyValueError::new_err("SchnorrSignature debe ser de 64 bytes"))?;
        Ok(Self(boxkey_core::SchnorrSignature(b)))
    }
}

#[pyclass(name = "NonceHandle")]
pub struct PyNonceHandle {
    inner: std::cell::RefCell<boxkey_core::NonceHandle>,
}

#[pymethods]
impl PyNonceHandle {
    fn identifier(&self) -> u32 {
        self.inner.borrow().identifier()
    }

    fn is_consumed(&self) -> bool {
        self.inner.borrow().is_consumed()
    }

    fn __repr__(&self) -> String {
        let h = self.inner.borrow();
        format!("NonceHandle(id={}, consumed={})", h.identifier(), h.is_consumed())
    }
}

#[pyclass(name = "SigningSession")]
#[derive(Clone)]
pub struct PySigningSession(pub boxkey_core::SigningSession);

#[pymethods]
impl PySigningSession {
    #[staticmethod]
    fn new(
        message_hash: Vec<u8>,
        group_public_key: &PyPublicKey,
        threshold: u8,
        commitments: Vec<PyCommitment>,
        verifying_share_points: Vec<(u32, Vec<u8>)>,
    ) -> PyResult<Self> {
        let hash = hash32(message_hash)?;
        let comms: Vec<boxkey_core::Commitment> = commitments.into_iter().map(|c| c.0).collect();
        let mut vsp = Vec::with_capacity(verifying_share_points.len());
        for (id, pt) in verifying_share_points {
            let arr = arr33(pt)?;
            vsp.push((id, arr));
        }
        let session = boxkey_core::SigningSession::new(hash, group_public_key.0, threshold, comms, vsp)
            .map_err(to_pyerr)?;
        Ok(Self(session))
    }

    fn __repr__(&self) -> String {
        format!("SigningSession({} signers, threshold={})", self.0.signer_count(), self.0.threshold)
    }
}

#[pyclass(name = "SignerInfo")]
#[derive(Clone)]
pub struct PySignerInfo(pub boxkey_core::SignerInfo);

#[pymethods]
impl PySignerInfo {
    #[getter]
    fn identifier(&self) -> u32 {
        self.0.identifier
    }

    #[getter]
    fn nonce_commitment(&self) -> PyCommitment {
        PyCommitment(self.0.nonce_commitment.clone())
    }

    #[getter]
    fn verifying_share_point(&self) -> Vec<u8> {
        self.0.verifying_share_point.to_vec()
    }
}

#[pyclass(name = "BoxKey")]
pub struct PyBoxKey;

#[pymethods]
impl PyBoxKey {
    #[new]
    fn new() -> Self {
        Self
    }

    #[staticmethod]
    fn generate_secret() -> PySecretShare {
        PySecretShare(<BoxKeyCoreImpl as BoxKeyCore>::generate_secret())
    }

    #[staticmethod]
    fn compute_commitments(
        share: &PySecretShare,
        threshold: u8,
        total_participants: u8,
    ) -> Vec<PyCommitment> {
        <BoxKeyCoreImpl as BoxKeyCore>::compute_commitments(&share.0, threshold, total_participants)
            .into_iter()
            .map(PyCommitment)
            .collect()
    }

    #[staticmethod]
    fn verify_commitments(
        commitments: Vec<PyCommitment>,
        proof_of_knowledge: Vec<u8>,
    ) -> PyResult<()> {
        let c: Vec<boxkey_core::Commitment> = commitments.into_iter().map(|x| x.0).collect();
        <BoxKeyCoreImpl as BoxKeyCore>::verify_commitments(&c, &proof_of_knowledge)
            .map_err(to_pyerr)
    }

    #[staticmethod]
    fn generate_shares(
        secret: &PySecretShare,
        participants: Vec<PyPublicKey>,
    ) -> PyResult<Vec<PyEncryptedShare>> {
        let pks: Vec<boxkey_core::PublicKey> = participants.into_iter().map(|x| x.0).collect();
        <BoxKeyCoreImpl as BoxKeyCore>::generate_shares(&secret.0, &pks)
            .map(|v| v.into_iter().map(PyEncryptedShare).collect())
            .map_err(to_pyerr)
    }

    #[staticmethod]
    fn verify_and_decrypt_share(
        encrypted: &PyEncryptedShare,
        my_key: &PySecretKey,
    ) -> PyResult<PyShare> {
        <BoxKeyCoreImpl as BoxKeyCore>::verify_and_decrypt_share(&encrypted.0, &my_key.0)
            .map(PyShare)
            .map_err(to_pyerr)
    }

    #[staticmethod]
    fn derive_public_key(shares: Vec<PyShare>) -> PyResult<PyPublicKey> {
        let s: Vec<boxkey_core::Share> = shares.into_iter().map(|x| x.0).collect();
        <BoxKeyCoreImpl as BoxKeyCore>::derive_public_key(&s)
            .map(PyPublicKey)
            .map_err(to_pyerr)
    }

    #[staticmethod]
    fn derive_partial_public_key(share: &PyShare) -> PyPublicKey {
        PyPublicKey(<BoxKeyCoreImpl as BoxKeyCore>::derive_partial_public_key(
            &share.0,
        ))
    }

    #[staticmethod]
    fn generate_nonces(share: &PyShare) -> (PyNonceHandle, PyCommitment) {
        let (h, c) = <BoxKeyCoreImpl as BoxKeyCore>::generate_nonces(&share.0);
        let handle = PyNonceHandle {
            inner: std::cell::RefCell::new(h),
        };
        (handle, PyCommitment(c))
    }

    #[staticmethod]
    fn sign_partial(
        share: &PyShare,
        session: &PySigningSession,
        handle: &PyNonceHandle,
    ) -> PyResult<PyPartialSignature> {
        let mut inner = handle.inner.borrow_mut();
        <BoxKeyCoreImpl as BoxKeyCore>::sign_partial(&share.0, &session.0, &mut *inner)
            .map(PyPartialSignature)
            .map_err(to_pyerr)
    }

    #[staticmethod]
    fn aggregate_signatures(
        sigs: Vec<PyPartialSignature>,
        session: &PySigningSession,
    ) -> PyResult<PySchnorrSignature> {
        let s: Vec<boxkey_core::PartialSignature> = sigs.into_iter().map(|x| x.0).collect();
        <BoxKeyCoreImpl as BoxKeyCore>::aggregate_signatures(&s, &session.0)
            .map(PySchnorrSignature)
            .map_err(to_pyerr)
    }

    #[staticmethod]
    fn verify_schnorr(
        sig: &PySchnorrSignature,
        pubkey: &PyPublicKey,
        message_hash: Vec<u8>,
    ) -> PyResult<bool> {
        let hash = hash32(message_hash)?;
        Ok(<BoxKeyCoreImpl as BoxKeyCore>::verify_schnorr(
            &sig.0, &pubkey.0, &hash,
        ))
    }

    #[staticmethod]
    fn reshare_begin(
        old_share: &PyShare,
        new_participants: Vec<PyPublicKey>,
        new_threshold: u8,
    ) -> PyResult<Vec<PyEncryptedShare>> {
        let pks: Vec<boxkey_core::PublicKey> = new_participants.into_iter().map(|x| x.0).collect();
        <BoxKeyCoreImpl as BoxKeyCore>::reshare_begin(&old_share.0, &pks, new_threshold)
            .map(|v| v.into_iter().map(PyEncryptedShare).collect())
            .map_err(to_pyerr)
    }

    #[staticmethod]
    fn reshare_accept(encrypted: &PyEncryptedShare, my_new_key: &PySecretKey) -> PyResult<PyShare> {
        <BoxKeyCoreImpl as BoxKeyCore>::reshare_accept(&encrypted.0, &my_new_key.0)
            .map(PyShare)
            .map_err(to_pyerr)
    }
}

#[pyclass(name = "DkgResult")]
pub struct PyDkgResult {
    shares: Vec<PyShare>,
    keys: Vec<(PySecretKey, PyPublicKey)>,
}

#[pymethods]
impl PyDkgResult {
    #[getter]
    fn shares(&self) -> Vec<PyShare> {
        self.shares.clone()
    }

    #[getter]
    fn keys(&self) -> Vec<(PySecretKey, PyPublicKey)> {
        self.keys.clone()
    }
}

#[pyfunction]
fn run_dkg(n: u8, t: u8) -> PyDkgResult {
    let (shares, keys) = boxkey_core::dkg::run_dkg(n, t);
    PyDkgResult {
        shares: shares.into_iter().map(PyShare).collect(),
        keys: keys
            .into_iter()
            .map(|(sk, pk)| (PySecretKey(sk), PyPublicKey(pk)))
            .collect(),
    }
}

#[pyfunction]
fn generate_participant_key() -> (PySecretKey, PyPublicKey) {
    let (sk, pk) = boxkey_core::dkg::generate_participant_key();
    (PySecretKey(sk), PyPublicKey(pk))
}

#[pymodule]
fn boxkey(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyBoxKey>()?;
    m.add_class::<PySecretShare>()?;
    m.add_class::<PyCommitment>()?;
    m.add_class::<PyEncryptedShare>()?;
    m.add_class::<PyShare>()?;
    m.add_class::<PyPublicKey>()?;
    m.add_class::<PySecretKey>()?;
    m.add_class::<PyPartialSignature>()?;
    m.add_class::<PySchnorrSignature>()?;
    m.add_class::<PyNonceHandle>()?;
    m.add_class::<PySigningSession>()?;
    m.add_class::<PySignerInfo>()?;
    m.add_class::<PyDkgResult>()?;
    m.add_function(wrap_pyfunction!(run_dkg, m)?)?;
    m.add_function(wrap_pyfunction!(generate_participant_key, m)?)?;
    Ok(())
}