use std::borrow::Cow;
use std::collections::HashSet;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use clap::Parser;
use regex::bytes::RegexBuilder;
use serde::{Deserialize, Deserializer, Serialize};
use tokio::fs::File;
use tokio::io::{stdin, stdout, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{ChildStdin, ChildStdout, Command};

#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct Args {
    #[arg(long, help = "Disable demangling in symbolized output")]
    no_demangle: bool,
    #[arg(help = "The files to read, or none if reading from stdin")]
    files: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct LLVMAddrSymbol {
    #[serde(deserialize_with = "non_zero")]
    column: Option<u64>,
    #[serde(deserialize_with = "non_empty")]
    file_name: Option<String>,
    #[serde(deserialize_with = "non_empty")]
    function_name: Option<String>,
    #[serde(deserialize_with = "non_zero")]
    line: Option<u64>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct LLVMAddrEntry {
    #[serde(default)]
    symbol: Vec<LLVMAddrSymbol>,
}

fn non_zero<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    let v: u64 = Deserialize::deserialize(deserializer)?;
    Ok((v != 0).then_some(v))
}

fn non_empty<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let v: &str = Deserialize::deserialize(deserializer)?;
    Ok((!v.is_empty()).then(|| v.to_string()))
}

struct FileOffsetResolver {
    symbolizer_in: ChildStdin,
    symbolizer_out: BufReader<ChildStdout>,
    path: PathBuf,
}

impl FileOffsetResolver {
    async fn new<P: AsRef<Path>>(path: P, demangle: bool) -> Result<Self, std::io::Error> {
        {
            let mut stdout = stdout();
            stdout.write_all(b"Applying debuginfo for ").await.unwrap();
            stdout
                .write_all(path.as_ref().as_os_str().as_bytes())
                .await
                .unwrap();
            stdout.write_u8(b'\n').await.unwrap();
        }
        let _ = Command::new("debuginfod-find")
            .arg("debuginfo")
            .arg(path.as_ref().as_os_str())
            //            .stdout(Stdio::null())
            .status()
            .await;
        let mut cmd = if let Some(symbolizer) = std::env::var_os("LLVM_SYMBOLIZER") {
            Command::new(symbolizer)
        } else {
            Command::new("llvm-symbolizer")
        };
        if demangle {
            cmd.arg("--demangle");
        } else {
            cmd.arg("--no-demangle");
        }
        let mut symbolizer = cmd
            .args([
                "--debuginfod",
                "--inlines",
                "--relative-address",
                "--output-style=JSON",
                "-e",
            ])
            .arg(path.as_ref().as_os_str())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .stdin(Stdio::piped())
            .spawn()
            .expect("unable to spawn llvm-symbolizer; please install llvm-symbolizer or set LLVM_SYMBOLIZER");
        let symbolizer_in = symbolizer.stdin.take().unwrap();
        let symbolizer_out = symbolizer.stdout.take().unwrap();
        let symbolizer_out = BufReader::new(symbolizer_out);

        Ok(Self {
            symbolizer_in,
            symbolizer_out,
            path: path.as_ref().to_path_buf(),
        })
    }

    async fn resolve_symbol(&mut self, addr: u64) -> Vec<LLVMAddrSymbol> {
        // avoid looking up private directories
        if self.path.is_absolute() {
            if self
                .symbolizer_in
                .write_all(format!("{:#x}\n", addr).as_bytes())
                .await
                .is_ok()
            {
                let mut line = String::new();
                if self.symbolizer_out.read_line(&mut line).await.is_ok() {
                    if let Ok(entry) = serde_json::from_str::<LLVMAddrEntry>(&line) {
                        return entry.symbol;
                    }
                }
            }
        }
        Vec::new()
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    let args = Args::parse();

    let re = RegexBuilder::new(r"^(.+?) \((\/.*)\+0x([0-9a-f]+)\)\s*(?:\(BuildId:.+)?$")
        .multi_line(true)
        .build()
        .expect("This is a valid regex.");

    let source = if !args.files.is_empty() {
        let mut combined = Vec::new();
        for filename in args.files {
            let mut file = File::open(filename).await?;
            file.read_to_end(&mut combined).await?;
        }
        combined
    } else {
        let mut source = Vec::new();
        stdin().read_to_end(&mut source).await?;
        source
    };

    let mut plain = Vec::new();
    let mut requiring_transform = Vec::new();

    let mut observed_paths = HashSet::new();

    let mut last = 0;
    for (i, item) in re.captures_iter(&source).enumerate() {
        let mut captures = item.iter();
        let actual = captures
            .next()
            .expect("if it's a capture, we must have the implicit group")
            .expect("it is unconditional");
        plain.push(&source[last..actual.start()]);
        last = actual.end();

        let prefix = captures
            .next()
            .expect("must have a set of spaces")
            .expect("it is unconditional")
            .as_bytes();
        let path = core::str::from_utf8(
            captures
                .next()
                .expect("we must have a path")
                .expect("it is unconditional")
                .as_bytes(),
        )?;
        let offset: u64 = u64::from_str_radix(
            core::str::from_utf8(
                captures
                    .next()
                    .expect("we must have an offset")
                    .expect("it is unconditional")
                    .as_bytes(),
            )?,
            16,
        )?;

        observed_paths.insert(path);

        requiring_transform.push((i, prefix, actual.as_bytes(), path, offset));
    }
    plain.push(&source[last..]);

    let mut transformed = Vec::new();

    for path in observed_paths {
        if let Ok(mut resolver) = FileOffsetResolver::new(path, !args.no_demangle).await {
            for &(i, prefix, actual, _, offset) in requiring_transform
                .iter()
                .filter(|(_, _, _, entry_path, _)| *entry_path == path)
            {
                let frames = resolver.resolve_symbol(offset).await;
                if !frames.is_empty() {
                    for (inline, frame) in frames.into_iter().rev().enumerate().rev() {
                        let mut completed = Vec::from(prefix);
                        if inline != 0 {
                            write!(&mut completed, "inlined ")?;
                        }

                        if let Some(f) = frame.function_name.as_ref() {
                            write!(&mut completed, "in {f}")?;
                            match &frame {
                                LLVMAddrSymbol {
                                    file_name: Some(file_path),
                                    line: Some(line_number),
                                    ..
                                } => write!(&mut completed, " {}:{line_number}", file_path)?,
                                LLVMAddrSymbol {
                                    file_name: Some(file_path),
                                    ..
                                } => write!(&mut completed, " {}", file_path)?,
                                _ => write!(&mut completed, " ({path}+0x{offset:x})")?,
                            };
                        } else {
                            write!(&mut completed, " ({path}+0x{offset:x})")?;
                        }

                        transformed.push((i, Cow::from(completed)))
                    }
                } else {
                    transformed.push((i, Cow::Borrowed(actual)));
                }
            }
            drop(resolver);
            continue;
        }
        for &(i, _, actual, _, _) in requiring_transform
            .iter()
            .filter(|(_, _, _, entry_path, _)| *entry_path == path)
        {
            transformed.push((i, Cow::Borrowed(actual)));
        }
    }

    transformed.sort_by_key(|&(i, _)| i);

    let mut transformed_iter = transformed.into_iter();
    let mut last_transformed = transformed_iter.next();

    let mut stdout = stdout();
    for (i, plain) in plain.into_iter().enumerate() {
        stdout.write_all(plain).await?;
        if let Some((j, transformed)) = last_transformed {
            if i != j {
                last_transformed = Some((j, transformed));
                continue;
            }
            stdout.write_all(&transformed).await?;
            last_transformed = None;
            for (h, transformed) in transformed_iter.by_ref() {
                if h == j {
                    stdout.write_u8(b'\n').await?;
                    stdout.write_all(&transformed).await?;
                } else {
                    last_transformed = Some((h, transformed));
                    break;
                }
            }
        }
    }

    Ok(())
}
