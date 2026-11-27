use amaru::Config;
use std::{error::Error, path::Path};
use yara_engine::YaraEngine;

pub(crate) fn run(config_path: &Path) -> Result<(), Box<dyn Error>> {
    let config = Config::load(config_path)?;
    let rules = config_path.with_file_name(config.yara_rules_path);
    YaraEngine::new(rules)?.verify_eicar()?;
    println!("EICAR_Test_File detected the test sample and cleared the negative control.");
    Ok(())
}
