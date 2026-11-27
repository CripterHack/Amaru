use super::*;
use tempfile::{tempdir, TempDir};

const CAPTURED: &[u8] = b"Amaru capture transaction fixture";
const REPLACEMENT: &[u8] = b"unrelated data at the original path";

struct CaptureFixture {
    _root: TempDir,
    store_dir: PathBuf,
    store: Quarantine,
    entry: QuarantineEntry,
    pending: PathBuf,
}

impl CaptureFixture {
    fn new() -> Self {
        let root = tempdir().unwrap();
        let store_dir = root.path().join("quarantine");
        let store = Quarantine::new(&store_dir, 1024, 30).unwrap();
        let source = root.path().join("source.txt");
        fs::write(&source, CAPTURED).unwrap();
        let entry = store.quarantine_file(&source, "test fixture").unwrap();
        let staging = entry
            .original_path
            .parent()
            .unwrap()
            .join(".amaru-quarantine-fixture");
        fs::create_dir(&staging).unwrap();
        Self {
            _root: root,
            store_dir,
            store,
            entry,
            pending: staging.join("pending"),
        }
    }

    fn journal_capture(&self) {
        self.store
            .write_transaction(&Transaction::Capture {
                entry: self.entry.clone(),
                pending: self.pending.clone(),
            })
            .unwrap();
    }

    fn reopen(&self) -> io::Result<Quarantine> {
        Quarantine::new(&self.store_dir, 1024, 30)
    }
}

#[test]
fn capture_restart_before_rename_keeps_the_original_and_sealed_copy() {
    let f = CaptureFixture::new();
    fs::write(&f.entry.original_path, CAPTURED).unwrap();
    f.journal_capture();

    let recovered = f.reopen().unwrap();
    assert_eq!(fs::read(&f.entry.original_path).unwrap(), CAPTURED);
    assert_eq!(
        recovered.list_entries().unwrap()[0].quarantine_name,
        f.entry.quarantine_name
    );
    assert!(f.store_dir.join(&f.entry.quarantine_name).is_file());
    assert!(f.reopen().is_ok());
}

#[test]
fn capture_restart_after_rename_finishes_only_the_matching_staged_file() {
    let f = CaptureFixture::new();
    fs::write(&f.pending, CAPTURED).unwrap();
    fs::write(&f.entry.original_path, REPLACEMENT).unwrap();
    f.journal_capture();

    let recovered = f.reopen().unwrap();
    assert!(!f.pending.exists());
    assert_eq!(fs::read(&f.entry.original_path).unwrap(), REPLACEMENT);
    assert_eq!(recovered.list_entries().unwrap().len(), 1);
    fs::remove_file(&f.entry.original_path).unwrap();
    f.reopen()
        .unwrap()
        .restore_file_by_id(&f.entry.quarantine_name)
        .unwrap();
    assert_eq!(fs::read(&f.entry.original_path).unwrap(), CAPTURED);
}

#[test]
fn changed_staged_content_and_an_occupied_original_are_both_preserved() {
    let f = CaptureFixture::new();
    let changed = b"changed before move";
    fs::write(&f.pending, changed).unwrap();
    fs::write(&f.entry.original_path, REPLACEMENT).unwrap();
    f.journal_capture();

    let error = f
        .reopen()
        .err()
        .expect("recovery needs an unoccupied destination");
    assert!(
        error.to_string().contains(&f.pending.display().to_string()),
        "{error}"
    );
    assert_eq!(fs::read(&f.entry.original_path).unwrap(), REPLACEMENT);
    assert_eq!(fs::read(&f.pending).unwrap(), changed);
}

#[test]
fn interrupted_discard_reconciles_its_entry_and_preserves_others() {
    let f = CaptureFixture::new();
    let unrelated = f.entry.original_path.with_file_name("other.txt");
    fs::write(&unrelated, REPLACEMENT).unwrap();
    let other = f
        .store
        .quarantine_file(&unrelated, "second fixture")
        .unwrap();
    f.store
        .write_transaction(&Transaction::Discard {
            id: f.entry.quarantine_name.clone(),
        })
        .unwrap();
    fs::remove_file(f.store_dir.join(&f.entry.quarantine_name)).unwrap();

    let recovered = f.reopen().unwrap();
    let remaining = recovered.list_entries().unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].quarantine_name, other.quarantine_name);
    f.reopen()
        .unwrap()
        .restore_file_by_id(&other.quarantine_name)
        .unwrap();
    assert_eq!(fs::read(unrelated).unwrap(), REPLACEMENT);
}
