use std::{
    fs, io,
    path::{Path, PathBuf},
};

pub fn read(data: &Path) -> io::Result<Vec<PathBuf>> {
    match fs::File::open(data.join("quick-paths.json")) {
        Ok(file) => {
            let paths: Vec<PathBuf> = serde_json::from_reader(file)?;
            if paths.is_empty() || paths.iter().any(|p| !p.is_absolute()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid saved quick scan locations",
                ));
            }
            Ok(paths)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let mut paths: Vec<_> = [
                dirs::download_dir(),
                dirs::desktop_dir(),
                dirs::document_dir(),
            ]
            .into_iter()
            .flatten()
            .filter(|p| p.is_dir())
            .collect();
            paths.sort();
            paths.dedup();
            Ok(paths)
        }
        Err(e) => Err(e),
    }
}

pub fn save(data: &Path, paths: Option<Vec<PathBuf>>) -> io::Result<Vec<PathBuf>> {
    let dest = data.join("quick-paths.json");
    if let Some(mut paths) = paths {
        if paths.is_empty() || paths.iter().any(|p| !p.is_absolute() || !p.is_dir()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Select existing folders with absolute paths",
            ));
        }
        paths.sort();
        paths.dedup();
        let mut roots = Vec::<PathBuf>::new();
        for path in paths {
            if !roots.iter().any(|parent| path.starts_with(parent)) {
                roots.push(path);
            }
        }
        fs::create_dir_all(data)?;
        let mut file = tempfile::NamedTempFile::new_in(data)?;
        serde_json::to_writer(&mut file, &roots)?;
        file.as_file().sync_all()?;
        file.persist(dest)?;
        Ok(roots)
    } else {
        match fs::remove_file(dest) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => read(data),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quick_locations_survive_restart_and_invalid_edits() {
        let root = tempfile::tempdir().unwrap();
        let a = root.path().join("scan");
        let b = a.join("nested");
        fs::create_dir_all(&b).unwrap();
        let data = root.path().join("settings");
        save(&data, Some(vec![a.clone(), b, a.clone()])).unwrap();
        assert!(save(&data, Some(vec!["relative".into()])).is_err());
        assert_eq!(read(&data).unwrap(), vec![a]);
        save(&data, None).unwrap();
        assert!(!data.join("quick-paths.json").exists());
    }
}
