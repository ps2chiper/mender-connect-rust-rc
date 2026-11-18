use std::env;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use mender_connect_rust::protocol::{ProtoMsg, decode, encode_message};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
struct Fixture {
    name: String,
    wire_hex: String,
    message: serde_json::Value,
}

fn main() -> Result<()> {
    let mut args = env::args_os().skip(1);
    let input = args
        .next()
        .map(PathBuf::from)
        .context("usage: export_frames INPUT_FIXTURES_JSON OUTPUT_JSON")?;
    let output = args
        .next()
        .map(PathBuf::from)
        .context("usage: export_frames INPUT_FIXTURES_JSON OUTPUT_JSON")?;
    if args.next().is_some() {
        bail!("usage: export_frames INPUT_FIXTURES_JSON OUTPUT_JSON");
    }

    let reader = BufReader::new(
        File::open(&input)
            .with_context(|| format!("failed to open input fixtures {}", input.display()))?,
    );
    let mut fixtures: Vec<Fixture> =
        serde_json::from_reader(reader).context("failed to parse input fixtures JSON")?;

    for fixture in &mut fixtures {
        let wire = hex::decode(&fixture.wire_hex)
            .with_context(|| format!("{}: invalid wire_hex", fixture.name))?;
        let message: ProtoMsg =
            decode(&wire).with_context(|| format!("{}: failed to decode frame", fixture.name))?;
        let encoded = encode_message(&message)
            .with_context(|| format!("{}: failed to encode frame", fixture.name))?;
        fixture.wire_hex = hex::encode(encoded);
    }

    let writer = BufWriter::new(
        File::create(&output)
            .with_context(|| format!("failed to create output fixtures {}", output.display()))?,
    );
    serde_json::to_writer_pretty(writer, &fixtures)
        .context("failed to write output fixtures JSON")?;

    Ok(())
}
