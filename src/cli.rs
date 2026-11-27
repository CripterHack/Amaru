use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Amaru: Next Generation Antivirus
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Check the EICAR rule using the configured signatures
    TestEicar {
        /// Path to the Amaru configuration file
        #[arg(long)]
        config: Option<PathBuf>,
    },

    /// Scan files or directories
    Scan {
        /// Path to scan
        #[arg(short, long)]
        path: PathBuf,

        /// Scan recursively
        #[arg(short, long, default_value_t = true)]
        recursive: bool,

        /// Use heuristic analysis
        #[arg(short = 'H', long, default_value_t = true)]
        heuristic: bool,

        /// Use Radare2 for static analysis
        #[arg(short = 'd', long, default_value_t = false)]
        radare2: bool,
    },

    /// Control real-time monitoring service
    Monitor {
        /// Action to perform with the service
        #[arg(short, long, value_enum)]
        action: MonitorAction,
    },

    /// Update virus signatures and YARA rules
    Update {
        /// Update YARA rules
        #[arg(short, long, default_value_t = false)]
        rules: bool,

        /// Update ClamAV database
        #[arg(short, long, default_value_t = false)]
        clamav: bool,

        /// Update heuristic patterns
        #[arg(short = 'H', long, default_value_t = false)]
        heuristic: bool,
    },

    /// Reload engine components
    Reload {
        /// Reload YARA rules
        #[arg(short, long, default_value_t = false)]
        rules: bool,
    },

    /// Analyze a file with advanced techniques
    Analyze {
        /// File to analyze
        #[arg(short, long)]
        file: PathBuf,

        /// Use Radare2
        #[arg(short, long, default_value_t = true)]
        radare2: bool,

        /// Use heuristic analysis
        #[arg(short = 'H', long, default_value_t = true)]
        heuristic: bool,
    },

    /// Internal Windows Service Control Manager entry point
    #[command(hide = true)]
    ServiceRun,

    /// Start, stop or check service status
    Service {
        /// Service action
        #[arg(short, long, value_enum)]
        action: ServiceAction,
    },

    /// Configure autostart options
    Autostart {
        /// Enable or disable autostart
        #[arg(short, long)]
        enable: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum MonitorAction {
    Start,
    Stop,
    Status,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum ServiceAction {
    Install,
    Uninstall,
    Start,
    Stop,
    Restart,
    Status,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn command_tree_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_self_test_and_its_optional_config() {
        for (args, expected) in [
            (vec!["amaru", "test-eicar"], None),
            (
                vec!["amaru", "test-eicar", "--config", "custom.toml"],
                Some(PathBuf::from("custom.toml")),
            ),
        ] {
            let cli = Cli::try_parse_from(args).unwrap();
            assert!(matches!(cli.command, Commands::TestEicar { config } if config == expected));
        }
        assert!(Cli::try_parse_from(["amaru", "test-eicar", "--unknown"]).is_err());
    }
}
