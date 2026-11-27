use std::collections::HashMap;
use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey};
use fs2::FileExt;
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::Builder;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum UpdateError {
    #[error("Actualización inválida: {0}")]
    Invalid(String),
    #[error("Error de red: {0}")]
    Network(#[from] reqwest::Error),
    #[error("Error de firma: {0}")]
    Signature(String),
    #[error("Error de sistema de archivos: {0}")]
    Filesystem(#[from] std::io::Error),
    #[error("Error de deserialización: {0}")]
    Deserialize(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleUpdate {
    pub version: String,
    pub timestamp: u64,
    pub rules: Vec<RuleFile>,
    pub signatures: Vec<Signature>,
    pub rollback_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleFile {
    pub path: String,
    pub hash: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub file_path: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateManifest {
    current_version: String,
    available_version: String,
    update_url: String,
    public_key: String,
}

pub struct Updater {
    rules_dir: PathBuf,
    backup_dir: PathBuf,
    public_key: VerifyingKey,
    client: reqwest::Client,
}

impl Updater {
    pub fn new(
        rules_dir: impl Into<PathBuf>,
        backup_dir: impl Into<PathBuf>,
        public_key: &[u8],
    ) -> Result<Self, UpdateError> {
        let bytes = public_key
            .try_into()
            .map_err(|_| UpdateError::Signature("Se requieren 32 bytes de clave pública".into()))?;
        let public_key =
            VerifyingKey::from_bytes(bytes).map_err(|e| UpdateError::Signature(e.to_string()))?;
        Ok(Self {
            rules_dir: rules_dir.into(),
            backup_dir: backup_dir.into(),
            public_key,
            client: reqwest::Client::new(),
        })
    }

    pub async fn check_updates(
        &self,
        manifest_url: &str,
    ) -> Result<Option<RuleUpdate>, UpdateError> {
        // The existing format signs rule bytes. HTTPS authenticates the descriptor,
        // including the filenames, URLs and version that the signatures do not cover.
        let metadata_client = reqwest::Client::builder().https_only(true).build()?;
        let manifest: UpdateManifest = serde_json::from_slice(
            &download(&metadata_client, manifest_url, MAX_DESCRIPTOR_BYTES).await?,
        )?;
        if version(&manifest.available_version)? <= self.current_version()? {
            return Ok(None);
        }
        let update: RuleUpdate = serde_json::from_slice(
            &download(&metadata_client, &manifest.update_url, MAX_DESCRIPTOR_BYTES).await?,
        )?;
        update.validate_structure()?;
        if update.version != manifest.available_version {
            return Err(UpdateError::Invalid(
                "Las versiones del manifiesto y del paquete difieren".into(),
            ));
        }
        Ok(Some(update))
    }

    /// Install a descriptor obtained through the trusted metadata channel.
    pub async fn apply_update(&self, update: RuleUpdate) -> Result<(), UpdateError> {
        let signatures = update.validated_signatures()?;
        let target_version = version(&update.version)?;
        let root_name = self
            .rules_dir
            .file_name()
            .ok_or_else(|| UpdateError::Invalid("Directorio de reglas inválido".into()))?;
        let parent = self
            .rules_dir
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::create_dir_all(parent)?;
        let parent = fs::canonicalize(parent)?;
        let live = parent.join(root_name);
        let mut state_name = root_name.to_os_string();
        state_name.push(".amaru-update");
        let state = parent.join(state_name);
        fs::create_dir_all(&state)?;
        check_entry(&state)?;

        // A persistent lock file serializes independent service processes.
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(state.join("lock"))?;
        FileExt::try_lock_exclusive(&lock)?;
        let previous = state.join("previous");
        if previous.exists() {
            if live.exists() {
                fs::remove_dir_all(&previous)?;
            } else {
                fs::rename(&previous, &live)?;
            }
        }
        if target_version <= self.current_version()? {
            return Err(UpdateError::Invalid(
                "La versión instalada ya es igual o más reciente".into(),
            ));
        }
        fs::create_dir_all(&live)?;
        check_entry(&live)?;
        fs::create_dir_all(&self.backup_dir)?;
        let backups = fs::canonicalize(&self.backup_dir)?;
        if backups.starts_with(&live) || backups.starts_with(&state) {
            return Err(UpdateError::Invalid(
                "Los backups deben estar fuera del árbol de reglas y de preparación".into(),
            ));
        }

        // Build the complete replacement on the same volume before changing live files.
        let staging = Builder::new().prefix("staging-").tempdir_in(&state)?;
        let replacement = staging.path().join("rules");
        copy_tree(&live, &replacement)?;
        for rule in &update.rules {
            let name = rule_path(&rule.path)?;
            let content = download(&self.client, &rule.url, MAX_RULE_BYTES).await?;
            if hex::encode(Sha256::digest(&content)) != rule.hash {
                return Err(UpdateError::Signature(format!(
                    "Hash incorrecto para {name}"
                )));
            }
            self.public_key
                .verify_strict(&content, &signatures[&name])
                .map_err(|_| UpdateError::Signature(format!("Firma incorrecta para {name}")))?;
            let dest = replacement.join(name);
            fs::create_dir_all(dest.parent().expect("path under replacement"))?;
            fs::write(dest, &content)?;
        }
        fs::write(replacement.join("version.txt"), &update.version)?;

        let backup = Builder::new().prefix("backup_").tempdir_in(backups)?;
        copy_tree(&live, backup.path())?;
        fs::rename(&live, &previous)?;
        if let Err(error) = fs::rename(&replacement, &live) {
            fs::rename(&previous, &live)?;
            return Err(error.into());
        }
        let _ = backup.into_path();
        if let Err(error) = fs::remove_dir_all(&previous) {
            log::warn!("La copia anterior queda pendiente de limpieza: {error}");
        }
        Ok(())
    }

    fn current_version(&self) -> Result<Version, UpdateError> {
        match fs::read_to_string(self.rules_dir.join("version.txt")) {
            Ok(text) => version(text.trim()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(Version::new(0, 0, 0)),
            Err(error) => Err(error.into()),
        }
    }
}

const MAX_DESCRIPTOR_BYTES: usize = 16 * 1024 * 1024;
const MAX_RULE_BYTES: usize = 100 * 1024 * 1024;

async fn download(
    client: &reqwest::Client,
    url: &str,
    limit: usize,
) -> Result<Vec<u8>, UpdateError> {
    let mut response = client.get(url).send().await?.error_for_status()?;
    let mut content = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > limit - content.len() {
            return Err(UpdateError::Invalid(format!(
                "La descarga supera el límite de {limit} bytes"
            )));
        }
        content.extend_from_slice(&chunk);
    }
    Ok(content)
}

fn version(text: &str) -> Result<Version, UpdateError> {
    Version::parse(text).map_err(|e| UpdateError::Invalid(e.to_string()))
}

impl RuleUpdate {
    /// Checks package structure. Authenticity is verified against each download during installation.
    pub fn validate_structure(&self) -> Result<(), UpdateError> {
        self.validated_signatures().map(|_| ())
    }

    fn validated_signatures(&self) -> Result<HashMap<String, Ed25519Signature>, UpdateError> {
        let mut signatures = HashMap::new();
        let mut names = std::collections::HashSet::new();
        for rule in &self.rules {
            let name = rule_path(&rule.path)?;
            if !names.insert(name.to_lowercase()) {
                return Err(UpdateError::Invalid(format!("Ruta duplicada: {name}")));
            }
        }
        for entry in &self.signatures {
            let name = rule_path(&entry.file_path)?;
            let signature = Ed25519Signature::from_slice(&entry.signature)
                .map_err(|e| UpdateError::Signature(e.to_string()))?;
            if signatures.insert(name, signature).is_some() {
                return Err(UpdateError::Signature("Firma duplicada".into()));
            }
        }
        if self.rules.is_empty() || signatures.len() != self.rules.len() {
            return Err(UpdateError::Signature(
                "Se requiere una firma por regla".into(),
            ));
        }
        for rule in &self.rules {
            if !signatures.contains_key(&rule_path(&rule.path)?) {
                return Err(UpdateError::Signature(format!(
                    "Falta la firma de {}",
                    rule.path
                )));
            }
        }
        Ok(signatures)
    }
}

// Normalize earlier packages created by Windows while rejecting Windows aliases
// on every host so a package resolves to the same files on each system.
fn rule_path(raw: &str) -> Result<String, UpdateError> {
    let name = raw.replace('\\', "/");
    for part in name.split('/') {
        let stem = part
            .split('.')
            .next()
            .unwrap_or("")
            .trim_end()
            .to_ascii_uppercase();
        if part.is_empty()
            || part.ends_with(['.', ' '])
            || part.contains([':', '*', '?', '"', '<', '>', '|'])
            || part.chars().any(char::is_control)
            || matches!(
                stem.as_str(),
                "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
            )
            || ["COM", "LPT"].iter().any(|prefix| {
                stem.strip_prefix(prefix).is_some_and(|n| {
                    matches!(
                        n,
                        "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                    )
                })
            })
        {
            return Err(UpdateError::Invalid(format!(
                "Ruta de firma inválida: {raw}"
            )));
        }
    }
    match Path::new(&name).extension().and_then(|ext| ext.to_str()) {
        Some("yar" | "yara") => Ok(name),
        _ => Err(UpdateError::Invalid(format!(
            "Extensión de regla inválida: {raw}"
        ))),
    }
}

fn check_entry(path: &Path) -> io::Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    #[cfg(windows)]
    let reparse_point = {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    };
    #[cfg(not(windows))]
    let reparse_point = false;
    if reparse_point || !(metadata.is_file() || metadata.is_dir()) {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("Entrada no regular: {}", path.display()),
        ));
    }
    Ok(metadata)
}

fn copy_tree(from: &Path, to: &Path) -> io::Result<()> {
    fs::create_dir_all(to)?;
    let mut pending = vec![(from.to_owned(), to.to_owned())];
    while let Some((source, destination)) = pending.pop() {
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let file = entry.path();
            let target = destination.join(entry.file_name());
            if check_entry(&file)?.is_dir() {
                fs::create_dir(&target)?;
                pending.push((file, target));
            } else {
                fs::copy(file, target)?;
            }
        }
    }
    Ok(())
}
