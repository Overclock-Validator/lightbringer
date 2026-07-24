//! Deterministic overlay simulator runner (nat-traversal.md §6.9):
//!
//! ```text
//! cargo run --bin overlay-sim --features sim -- --seed N [--scenario NAME]
//!           [--verbose] [--until-failure] [--list]
//! ```
//!
//! Runs a scenario under the discrete-event simulator and prints its trace
//! hash — the reproducibility witness: a failure is a `(seed, scenario)`
//! pair, replayable exactly.
#![allow(dead_code)]
#![allow(unused_imports)]

#[path = "types.rs"]
mod types;
#[path = "thread_manager/mod.rs"]
mod thread_manager;
#[path = "overlay/mod.rs"]
mod overlay;

use overlay::sim::scenario;

struct Args {
    seed: u64,
    scenario: String,
    verbose: bool,
    until_failure: bool,
    list: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        seed: 1,
        scenario: "two-node-lossy".to_string(),
        verbose: false,
        until_failure: false,
        list: false,
    };
    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--seed" => {
                let value = iter.next().ok_or("--seed requires a value")?;
                args.seed = value
                    .parse()
                    .map_err(|e| format!("invalid --seed {value}: {e}"))?;
            }
            "--scenario" => {
                args.scenario = iter.next().ok_or("--scenario requires a value")?;
            }
            "--verbose" => args.verbose = true,
            "--until-failure" => args.until_failure = true,
            "--list" => args.list = true,
            "--help" | "-h" => {
                return Err(format!(
                    "usage: overlay-sim [--seed N] [--scenario NAME] [--verbose] \
                     [--until-failure] [--list]\nscenarios: {}",
                    scenario::SCENARIOS.join(", ")
                ));
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(args)
}

fn main() {
    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Warn)
        .env()
        .init()
        .ok();

    let args = match parse_args() {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    };

    if args.list {
        for name in scenario::SCENARIOS {
            println!("{name}");
        }
        return;
    }

    let mut seed = args.seed;
    loop {
        let Some(outcome) = scenario::run(&args.scenario, seed, args.verbose) else {
            eprintln!(
                "unknown scenario {:?}; available: {}",
                args.scenario,
                scenario::SCENARIOS.join(", ")
            );
            std::process::exit(2);
        };
        println!(
            "scenario={} seed={} events={} ok={} trace_hash={}",
            outcome.name, outcome.seed, outcome.events, outcome.ok, outcome.trace_hash
        );
        println!("  {}", outcome.summary);

        if !outcome.ok {
            std::process::exit(1);
        }
        if !args.until_failure {
            break;
        }
        seed += 1;
    }
}
