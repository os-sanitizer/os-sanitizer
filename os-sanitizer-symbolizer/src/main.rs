use either::Either;
use regex::bytes::RegexBuilder;
use std::borrow::Cow;
use std::collections::HashSet;
use std::future::{ready, Future};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::fs;
use tokio::io::{stdin, stdout, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use wholesym::{
    Error, FrameDebugInfo, FramesLookupResult, SymbolManager, SymbolManagerConfig, SymbolMap,
};

pub struct FileOffsetResolver {
    mapping: SymbolMap,
    path: PathBuf,
}

impl FileOffsetResolver {
    async fn new<P: AsRef<Path>>(manager: &SymbolManager, path: P) -> Result<Self, Error> {
        {
            let mut stdout = stdout();
            stdout.write(b"Applying debuginfo for ").await.unwrap();
            stdout
                .write(path.as_ref().as_os_str().as_bytes())
                .await
                .unwrap();
            stdout.write_u8(b'\n').await.unwrap();
        }
        let _ = Command::new("debuginfod-find")
            .arg("debuginfo")
            .arg(path.as_ref().as_os_str())
            .stdout(Stdio::null())
            .status()
            .await;

        let mapping = manager
            .load_symbol_map_for_binary_at_path(path.as_ref(), None)
            .await?;
        Ok(Self {
            mapping,
            path: path.as_ref().to_path_buf(),
        })
    }

    fn resolve_symbol<'a>(
        &'a self,
        manager: &'a SymbolManager,
        addr: u64,
    ) -> impl Future<Output = Option<Vec<FrameDebugInfo>>> + 'a {
        // avoid looking up private directories
        if self.path.is_absolute() && !self.path.starts_with("/home") {
            if let Some(info) = self.mapping.lookup_offset(addr) {
                match info.frames {
                    FramesLookupResult::Available(frames) => {
                        return Either::Left(ready(Some(frames)))
                    }
                    FramesLookupResult::External(ext) => {
                        let origin = self.mapping.symbol_file_origin();
                        return Either::Right(async move {
                            manager.lookup_external(&origin, &ext).await
                        });
                    }
                    FramesLookupResult::Unavailable => {}
                }
            }
        }
        Either::Left(ready(None))
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let mut config = SymbolManagerConfig::default().use_debuginfod(false);

    if let Some(home) = std::env::var_os("HOME") {
        let cache = Path::new(&home).join(".cache/debuginfod_client");
        if cache.exists() {
            config = SymbolManagerConfig::default()
                .use_debuginfod(true)
                .debuginfod_cache_dir_if_not_installed(cache)
        }
    }

    let manager = SymbolManager::with_config(config);

    let re = RegexBuilder::new(r"^(.+)([0-9]+):\s+(/.*)\+0x([0-9a-f]+)$")
        .multi_line(true)
        .build()
        .expect("This is a valid regex.");

    let source = if let Some(filename) = std::env::args_os().nth(1) {
        fs::read(filename).await?
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
        let frame_no: usize = core::str::from_utf8(
            captures
                .next()
                .expect("we must have a frame number")
                .expect("it is unconditional")
                .as_bytes(),
        )?
        .parse()?;
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

        requiring_transform.push((i, prefix, actual.as_bytes(), frame_no, path, offset));
    }
    plain.push(&source[last..]);

    let mut transformed = Vec::new();

    for path in observed_paths {
        if !path.starts_with("/home") {
            if let Ok(resolver) = FileOffsetResolver::new(&manager, path).await {
                for &(i, prefix, actual, frame_no, _, offset) in requiring_transform
                    .iter()
                    .filter(|(_, _, _, _, entry_path, _)| *entry_path == path)
                {
                    if let Some(frames) = resolver
                        .resolve_symbol(&manager, offset)
                        .await
                        .and_then(|frames| (!frames.is_empty()).then_some(frames))
                    {
                        for (inline, frame) in frames.into_iter().rev().enumerate().rev() {
                            let frame_no = if inline == 0 {
                                format!("{frame_no}")
                            } else {
                                format!("{frame_no}[{inline}]")
                            };
                            let maybe_function = frame.function.as_ref().map_or_else(
                                || Cow::from(format!("{path}+0x{offset:x}")),
                                Cow::from,
                            );
                            let rendered = match &frame {
                                FrameDebugInfo {
                                    file_path: Some(file_path),
                                    line_number: Some(line_number),
                                    ..
                                } => format!(
                                    "{frame_no}:\t{maybe_function} ({}:{line_number})",
                                    file_path.display_path()
                                ),
                                FrameDebugInfo {
                                    file_path: Some(file_path),
                                    ..
                                } => format!(
                                    "{frame_no}:\t{maybe_function} ({})",
                                    file_path.display_path()
                                ),
                                _ => format!("{frame_no}:\t{maybe_function}",),
                            };

                            let mut completed = Vec::from(prefix);
                            completed.extend(rendered.into_bytes());

                            transformed.push((i, Cow::from(completed)))
                        }
                    } else {
                        transformed.push((i, Cow::Borrowed(actual)));
                    }
                }
                continue;
            }
        }
        for &(i, _, actual, _, _, _) in requiring_transform
            .iter()
            .filter(|(_, _, _, _, entry_path, _)| *entry_path == path)
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
            while let Some((h, transformed)) = transformed_iter.next() {
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
