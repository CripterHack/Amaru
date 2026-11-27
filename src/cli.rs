use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Amaru: Next Generation Antivirus
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub(crate) struct Cli {
    /// Path to the Amaru configuration file
    #[arg(long, global = true)]
    pub(crate) config: Option<PathBuf>,

    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Check the EICAR rule using the configured signatures
    TestEicar,

    /// Scan files or directories
    Scan {
        /// Path to scan
        #[arg(short, long)]
        path: PathBuf,

        /// Scan recursively
        #[arg(short, long, default_value_t = true, action=clap::ArgAction::Set, num_args=0..=1, default_missing_value="true", require_equals=true)]
        recursive: bool,

        /// Use heuristic analysis
        #[arg(short = 'H', long, action=clap::ArgAction::Set, num_args=0..=1, default_missing_value="true", require_equals=true)]
        heuristic: Option<bool>,

        /// Use Radare2 for static analysis
        #[arg(short = 'd', long, default_value_t = false, action=clap::ArgAction::Set, num_args=0..=1, default_missing_value="true", require_equals=true)]
        radare2: bool,
    },

    /// Schedule a scan in Windows Task Scheduler
    Schedule(ScheduleArgs),

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
        #[arg(short = 'H', long, default_value_t = false, action=clap::ArgAction::Set, num_args=0..=1, default_missing_value="true", require_equals=true)]
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
        #[arg(short, long, default_value_t = true, action=clap::ArgAction::Set, num_args=0..=1, default_missing_value="true", require_equals=true)]
        radare2: bool,

        /// Use heuristic analysis
        #[arg(short = 'H', long, action=clap::ArgAction::Set, num_args=0..=1, default_missing_value="true", require_equals=true)]
        heuristic: Option<bool>,
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
        #[arg(short, long, action=clap::ArgAction::Set, num_args=0..=1, default_missing_value="true", require_equals=true)]
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

#[derive(Debug, Args)]
#[command(group(clap::ArgGroup::new("mode").required(true).multiple(false).args(["daily", "weekly", "status", "disable"])))]
pub(crate) struct ScheduleArgs {
    #[arg(long, requires_all = ["time", "path"])]
    daily: bool,
    #[arg(long, requires_all = ["time", "path", "day"])]
    weekly: bool,
    #[arg(long)]
    pub(crate) status: bool,
    #[arg(long)]
    pub(crate) disable: bool,
    /// Local wall-clock time in HH:mm format
    #[arg(long, conflicts_with_all = ["status", "disable"])]
    time: Option<String>,
    /// Sunday through Saturday
    #[arg(long, value_enum, ignore_case = true, requires = "weekly", conflicts_with_all = ["daily", "status", "disable"])]
    day: Option<Weekday>,
    /// File or directory to scan
    #[arg(long, conflicts_with_all = ["status", "disable"])]
    path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Weekday {
    Sunday,
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
}

impl ScheduleArgs {
    pub(crate) fn schedule(&self) -> Result<amaru::scheduler::Schedule, String> {
        let path = self.path.as_ref().ok_or("Specify a path to scan")?;
        let schedule = amaru::scheduler::Schedule {
            frequency: if self.daily { "daily" } else { "weekly" }.into(),
            time: self
                .time
                .clone()
                .ok_or("Specify the local time in HH:mm format")?,
            day: self.day.map_or(0, |day| day as u8),
            path: Some(std::path::absolute(path).map_err(|e| e.to_string())?),
        };
        schedule.validate()?;
        Ok(schedule)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn schedule_checks_mode_time_day_and_target() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().to_str().unwrap();
        for (mode, day, expected) in [
            ("--daily", None, 0),
            ("--weekly", Some("sUndAy"), 0),
            ("--weekly", Some("Friday"), 5),
        ] {
            let mut args = vec!["amaru", "schedule", mode, "--time", "02:00", "--path", path];
            if let Some(day) = day {
                args.extend(["--day", day]);
            }
            let Commands::Schedule(options) = Cli::try_parse_from(args).unwrap().command else {
                panic!()
            };
            let schedule = options.schedule().unwrap();
            assert_eq!(schedule.day, expected);
            assert_eq!(schedule.path.as_deref(), Some(directory.path()));
        }
        for args in [
            vec!["--weekly", "--time", "02:00", "--path", path],
            vec!["--daily", "--weekly"],
            vec!["--status", "--path", path],
            vec![
                "--daily", "--day", "Monday", "--time", "02:00", "--path", path,
            ],
            vec!["--disable", "--status"],
        ] {
            assert!(
                Cli::try_parse_from(
                    ["amaru", "schedule"]
                        .into_iter()
                        .chain(args.iter().copied())
                )
                .is_err(),
                "{args:?}"
            );
        }
        let Commands::Schedule(invalid) = Cli::try_parse_from([
            "amaru", "schedule", "--daily", "--time", "25:01", "--path", path,
        ])
        .unwrap()
        .command
        else {
            panic!()
        };
        assert!(invalid.schedule().is_err());
    }

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
            assert!(matches!(cli.command, Commands::TestEicar));
            assert_eq!(cli.config, expected);
        }
        assert!(Cli::try_parse_from(["amaru", "test-eicar", "--unknown"]).is_err());
    }
}
