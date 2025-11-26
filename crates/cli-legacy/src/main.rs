#![allow(deprecated)]

use clap::Parser;
use colored::Colorize;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use kfc::container::{KFCFile, KFCReader, KFCWriter};
use kfc::resource::value::Value;
use kfc::guid::{ContentHash, Guid, ResourceId};
use kfc::reflection::{LookupKey, TypeRegistry};
use kfc::content::impact::bytecode::{ImpactAssembler, ImpactProgramData};
use kfc::content::impact::{ImpactProgram, TypeRegistryImpactExt};
use kfc::content::image::{PixelFormat, decode as decode_image, strip_content_wrapper, size_of_format};
use kfc::content::audio::deserialize_audio;
use thiserror::Error;
use std::collections::{HashMap, HashSet};
use std::env::current_exe;
use std::fs::File;
use std::io::{BufReader, BufWriter, Cursor, Write};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::atomic::{AtomicBool, AtomicU32};
use std::sync::Mutex;
use walkdir::WalkDir;

use crate::cli::{Cli, CommandImpact, Commands};
use crate::logging::*;

mod cli;
mod logging;
mod util;

macro_rules! fatal {
    ($($arg:tt)*) => {
        return Err(Error(format!($($arg)*)))
    };
}

#[derive(Debug)]
struct Error(String);

impl std::error::Error for Error {}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

fn main() {
    let cli = Cli::parse();
    let thread_count = cli.threads;

    let result = match cli.commands {
        Commands::Unpack {
            game_directory,
            file_name,
            output,
            filter,
            stdout,
        } => {
            set_logging(!stdout);
            unpack(
                &game_directory,
                file_name.as_deref(),
                output.as_deref(),
                stdout,
                filter,
                thread_count
            )
        }
        Commands::Repack {
            game_directory,
            file_name,
            input,
            stdin,
        } => {
            repack(
                &game_directory,
                file_name.as_deref(),
                input.as_deref(),
                stdin,
                thread_count
            )
        }
        Commands::ExtractTypes {
            game_directory,
            file_name,
        } => {
            extract_types(&game_directory, file_name.as_deref())
        }
        Commands::Restore {
            game_directory,
            file_name,
        } => {
            revert_repack(
                &game_directory,
                file_name.as_deref(),
                false
            )
        }
        Commands::Impact(impact) => match impact {
            CommandImpact::Assemble {
                input,
                output,
                guid,
            } => {
                assemble_impact(&input, output.as_deref(), guid.as_deref())
            }
            CommandImpact::Disassemble {
                input,
                output,
            } => {
                disassemble_impact(&input, output.as_deref())
            }
            CommandImpact::ExtractNodes => {
                extract_nodes()
            }
        }
        Commands::ExtractContent {
            game_directory,
            file_name,
            output,
            filter,
            convert,
            organize,
            use_debug_names,
            mipmaps,
            registry,
            limit,
        } => {
            extract_content(
                &game_directory,
                file_name.as_deref(),
                &output,
                filter,
                convert,
                organize,
                use_debug_names,
                mipmaps,
                registry.as_deref(),
                thread_count,
                limit
            )
        }
        Commands::ImportContent {
            game_directory,
            file_name,
            input,
        } => {
            import_content(
                &game_directory,
                file_name.as_deref(),
                &input,
                thread_count
            )
        }
    };

    match result {
        Ok(()) => {},
        Err(e) => {
            error!("{}", e);
            exit(1);
        }
    }
}

fn unpack(
    game_dir: &Path,
    file_name: Option<&str>,
    output_dir: Option<&Path>,
    stdout: bool,
    filter: String,
    thread_count: u8
) -> Result<(), Error> {
    if !game_dir.exists() {
        fatal!("Game directory does not exist: {}", game_dir.display());
    }

    if output_dir.map(|x| !x.exists()).unwrap_or(false) {
        fatal!("Output directory does not exist: {}", output_dir.unwrap().display());
    }

    let file_name = get_file_name(game_dir, file_name)?;
    let file_path = get_file(game_dir, Some(&file_name), "kfc")?;
    let type_registry = load_type_registry(Some(game_dir), Some(&file_name), true)?;

    let file = match KFCFile::from_path(&file_path, false) {
        Ok(dir) => dir,
        Err(e) => fatal!("Failed to read {}: {}", file_path.display(), e)
    };

    enum Filter<'a> {
        All,
        ByType(&'a str),
        ByGuid(ResourceId)
    }

    let mut filters = Vec::new();

    for filter in filter.split(',') {
        let entry = filter.trim();

        if entry.is_empty() {
            continue;
        }

        if entry == "*" {
            filters.clear();
            filters.push(Filter::All);
            break;
        } else if let Some(ty) = entry.strip_prefix('t') {
            filters.push(Filter::ByType(ty));
        } else {
            match ResourceId::parse_qualified(entry) {
                Some(guid) => filters.push(Filter::ByGuid(guid)),
                None => fatal!("`{}` is not a valid guid", entry),
            }
        }
    }

    let mut guids = HashSet::new();

    for filter in &filters {
        match filter {
            Filter::All => {
                guids = file.resources().keys().iter().collect();
                break;
            }
            Filter::ByType(type_name) => {
                let type_hash = match type_registry.get_by_name(LookupKey::Qualified(type_name)) {
                    Some(t) => t.qualified_hash,
                    None => {
                        fatal!("Type not found: {}", type_name);
                    }
                };

                for guid in file.resources().keys() {
                    if type_hash == guid.type_hash() {
                        guids.insert(guid);
                    }
                }
            }
            Filter::ByGuid(guid) => {
                if file.resources().contains_key(guid) {
                    guids.insert(guid);
                } else {
                    fatal!("GUID not found: {}", guid);
                }
            }
        }
    }

    let kfc_reader = match KFCReader::new(game_dir, &file_name) {
        Ok(reader) => reader,
        Err(e) => fatal!("Failed to open {}: {}", file_path.display(), e)
    };

    if let Some(output_dir) = output_dir {
        info!("Unpacking {} to {}", file_path.display(), output_dir.display());

        unpack_files(
            &kfc_reader,
            &type_registry,
            output_dir,
            guids,
            thread_count
        )
    } else if stdout {
        unpack_stdout(
            &kfc_reader,
            &type_registry,
            guids,
            thread_count
        )
    } else {
        fatal!("No output directory specified")
    }
}

fn unpack_files(
    kfc_reader: &KFCReader,
    type_registry: &TypeRegistry,
    output_dir: &Path,
    guids: HashSet<&ResourceId>,
    thread_count: u8
) -> Result<(), Error> {
    let pb = ProgressBar::new(guids.len() as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template(&format!("{} Unpacking... [{{bar:40}}] {{pos:>7}}/{{len:7}} {{msg}}", "info:".blue().bold()))
        .unwrap()
        .progress_chars("##-"));

    let total = guids.len() as u32;
    let pending_guids = Mutex::new(guids.into_iter().collect::<Vec<_>>());
    let failed_unpacks = AtomicU32::new(0);
    let start = std::time::Instant::now();
    let names = Mutex::new(HashSet::new());

    std::thread::scope(|s| {
        let mut handles = Vec::new();

        for i in 0..thread_count {
            let failed_unpacks = &failed_unpacks;
            let pending_guids = &pending_guids;
            let output_dir = &output_dir;
            let pb = &pb;
            let names = &names;

            let handle = s.spawn(move || {
                let mut buf = Vec::with_capacity(1024);
                let mut reader = match kfc_reader.new_cursor() {
                    Ok(file) => file,
                    Err(e) => {
                        pb.suspend(|| {
                            error!("Failed to open {}: {}", kfc_reader.kfc_path().display(), e);
                            error!("Worker #{} has been suspended", i);
                        });
                        return;
                    }
                };

                loop {
                    let guid = {
                        let mut lock = pending_guids.lock().unwrap();

                        if let Some(entry) = lock.pop() {
                            entry
                        } else {
                            break;
                        }
                    };

                    let result: anyhow::Result<()> = (|| {
                        buf.clear();
                        let descriptor = match crate::util::read_descriptor_into(
                            &mut reader,
                            type_registry,
                            guid,
                            &mut buf
                        )? {
                            Some(d) => d,
                            None => {
                                pb.suspend(|| {
                                    warn!("Skipping descriptor (not found): {}", guid.to_qualified_string());
                                });
                                return Ok(());
                            }
                        };

                        let r#type = type_registry.get_by_hash(LookupKey::Qualified(guid.type_hash()))
                            .ok_or_else(|| anyhow::anyhow!("Type not found: {:0>8x}", guid.type_hash()))?;
                        let type_name: &str = &r#type.name;
                        let parent = output_dir.join(type_name);

                        if !parent.exists() {
                            std::fs::create_dir_all(&parent)?;
                        }

                        let name = guid.to_qualified_string();
                        let mut file_name = format!("{}.json", name);
                        let mut file_names = names.lock().unwrap();
                        let mut i = 0;

                        while file_names.contains(&file_name) {
                            i += 1;
                            file_name = format!("{}.{}.json", name, i);
                        }

                        file_names.insert(file_name.clone());

                        drop(file_names);

                        let path = parent.join(&file_name);
                        let file = match File::create(&path) {
                            Ok(file) => file,
                            Err(e) => {
                                pb.suspend(|| {
                                    error!("Failed to create file with name `{}`: {}", file_name, e);
                                });
                                return Ok(());
                            }
                        };
                        let writer = BufWriter::new(file);
                        serde_json::to_writer_pretty(writer, &descriptor)?;

                        Ok(())
                    })();

                    match result {
                        Ok(()) => {},
                        Err(e) => {
                            failed_unpacks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                            pb.suspend(|| {
                                error!("Error occurred while unpacking `{}`: {}", guid.to_qualified_string(), e);
                            });
                        }
                    }

                    pb.inc(1);
                }
            });

            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap()
        }
    });

    pb.finish_and_clear();

    let failed_unpacks = failed_unpacks.load(std::sync::atomic::Ordering::Relaxed);
    let end = std::time::Instant::now();

    info!("Unpacked a total of {}/{} descriptors in {:?}", total - failed_unpacks, total, end - start);

    Ok(())
}

fn unpack_stdout(
    kfc_reader: &KFCReader,
    type_registry: &TypeRegistry,
    guids: HashSet<&ResourceId>,
    thread_count: u8
) -> Result<(), Error> {
    let pending_guids = Mutex::new(guids.into_iter().collect::<Vec<_>>());
    let (tx, rx) = std::sync::mpsc::sync_channel(1024);

    std::thread::scope(|s| {
        let mut handles = Vec::new();

        for _ in 0..thread_count {
            let tx = tx.clone();
            let pending_guids = &pending_guids;

            let handle = s.spawn(move || {
                let mut buf = Vec::with_capacity(1024);
                let mut reader = match kfc_reader.new_cursor() {
                    Ok(file) => file,
                    Err(e) => {
                        let error = serde_json::json!({
                            "$error": "KFCReaderError",
                            "$message": format!("Failed to open {}: {}", kfc_reader.kfc_path().display(), e),
                        }).to_string();

                        tx.send(error).unwrap();

                        return;
                    }
                };

                loop {
                    let guid = {
                        let mut lock = pending_guids.lock().unwrap();

                        if let Some(entry) = lock.pop() {
                            entry
                        } else {
                            break;
                        }
                    };

                    buf.clear();
                    let descriptor = match crate::util::read_descriptor_into(
                        &mut reader,
                        type_registry,
                        guid,
                        &mut buf
                    ) {
                        Ok(Some(d)) => match serde_json::to_string(&d) {
                            Ok(data) => data,
                            Err(e) => {
                                serde_json::json!({
                                    "$guid": guid.to_qualified_string(),
                                    "$error": "SerializationError",
                                    "$message": e.to_string(),
                                }).to_string()
                            }
                        },
                        Ok(None) => serde_json::json!({
                            "$guid": guid.to_qualified_string(),
                            "$error": "NotFound",
                        }).to_string(),
                        Err(e) => serde_json::json!({
                            "$guid": guid.to_qualified_string(),
                            "$error": "ReadError",
                            "$message": e.to_string(),
                        }).to_string()
                    };
                    let result = descriptor.to_string();

                    tx.send(result).unwrap();
                }
            });

            handles.push(handle);
        }

        drop(tx);

        let writer_handle = s.spawn(move || {
            let mut writer = std::io::stdout();

            while let Ok(data) = rx.recv() {
                match writer.write_all(data.as_bytes()) {
                    Ok(()) => {},
                    Err(e) => panic!("Failed to write to stdout: {}", e),
                }

                match writer.write_all(b"\n") {
                    Ok(()) => {},
                    Err(e) => panic!("Failed to write to stdout: {}", e),
                }
            }
        });

        match writer_handle.join() {
            Ok(()) => {},
            Err(e) => {
                fatal!("Writer thread panicked: {:?}", e)
            }
        }

        for handle in handles {
            handle.join().unwrap()
        }

        Ok(())
    })
}

fn validate_backup(
    kfc_path: &Path,
    kfc_path_bak: &Path
) -> Result<bool, Error> {
    let version_bak = match KFCFile::get_version_tag(kfc_path_bak) {
        Ok(file) => file,
        Err(_) => return Ok(false),
    };

    let version = match KFCFile::get_version_tag(kfc_path) {
        Ok(file) => file,
        Err(e) => fatal!("Failed to read {}: {}", kfc_path.display(), e)
    };

    Ok(version == version_bak)
}

fn repack(
    game_dir: &Path,
    file_name: Option<&str>,
    input_dir: Option<&Path>,
    stdin: bool,
    thread_count: u8
) -> Result<(), Error> {
    if !game_dir.exists() {
        fatal!("Game directory does not exist: {}", game_dir.display());
    }

    if input_dir.map(|x| !x.exists()).unwrap_or(false) {
        fatal!("Input directory does not exist: {}", input_dir.unwrap().display());
    }

    let kfc_path = get_file(game_dir, file_name, "kfc")?;
    let kfc_path_bak = get_file_opt(game_dir, file_name, "kfc.bak")?;

    if kfc_path_bak.exists() && !validate_backup(&kfc_path, &kfc_path_bak)? {
        warn!("Backup file is not valid, deleting it...");

        if !kfc_path_bak.is_file() {
            fatal!("Backup path is not a file, please remove it manually: {}", kfc_path_bak.display())
        }

        if let Err(e) = std::fs::remove_file(&kfc_path_bak) {
            fatal!("Failed to delete backup file: {}", e);
        }
    }

    if !kfc_path_bak.exists() {
        info!("Creating backup of {}...", kfc_path.display());

        match std::fs::copy(&kfc_path, &kfc_path_bak) {
            Ok(_) => {},
            Err(e) => fatal!("Failed to create backup: {}", e)
        }
    }

    let type_registry = load_type_registry(Some(game_dir), file_name, true)?;

    let mut ref_kfc_file = match KFCFile::from_path(&kfc_path_bak, false) {
        Ok(file) => file,
        Err(e) => fatal!("Failed to read {}: {}", kfc_path_bak.display(), e)
    };

    if let Some(input_dir) = input_dir {
        info!("Repacking {} to {}", input_dir.display(), kfc_path.display());

        let files = WalkDir::new(input_dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
            .map(|e| e.path().to_path_buf())
            .collect::<Vec<_>>();

        let result = repack_files(
            game_dir,
            file_name,
            &mut ref_kfc_file,
            files,
            &type_registry,
            thread_count
        );

        match result {
            Ok(()) => Ok(()),
            Err(e) => {
                error!("{}", e);
                revert_repack(game_dir, file_name, true)
            }
        }
    } else if stdin {
        info!("Repacking from stdin to {}", kfc_path.display());

        let result = repack_stdin(
            game_dir,
            file_name,
            &mut ref_kfc_file,
            &type_registry,
            thread_count
        );

        match result {
            Ok(()) => Ok(()),
            Err(e) => {
                error!("{}", e);
                revert_repack(game_dir, file_name, true)
            }
        }
    } else {
        fatal!("No input specified");
    }
}

fn repack_files(
    game_dir: &Path,
    file_name: Option<&str>,
    ref_kfc_file: &mut KFCFile,
    files: Vec<PathBuf>,
    type_registry: &TypeRegistry,
    thread_count: u8
) -> Result<(), Error> {
    if files.is_empty() {
        fatal!("No files found to repack");
    }

    let file_name = get_file_name(game_dir, file_name)?;
    let file_path = get_file(game_dir, Some(&file_name), "kfc")?;

    let mut writer = match KFCWriter::new_incremental(
        game_dir,
        &file_name,
        ref_kfc_file,
        type_registry
    ) {
        Ok(writer) => writer,
        Err(e) => fatal!("Failed to open {}: {}", file_path.display(), e)
    };

    let total = files.len() as u64;
    let mpb = MultiProgress::new();

    let pb_serialize = mpb.add(ProgressBar::new(total));
    pb_serialize.set_style(ProgressStyle::default_bar()
        .template(&format!("{} Serializing... [{{bar:40}}] {{pos:>7}}/{{len:7}} {{msg}}", "info:".blue().bold()))
        .unwrap()
        .progress_chars("##-"));

    let pb_write = mpb.add(ProgressBar::new(total));
    pb_write.set_style(ProgressStyle::default_bar()
        .template(&format!("{} Writing... [{{bar:40}}] {{pos:>7}}/{{len:7}} {{msg}}", "info:".blue().bold()))
        .unwrap()
        .progress_chars("##-"));

    let total = files.len() as u32;
    let pending_files = Mutex::new(files.into_iter().collect::<Vec<_>>());
    let (tx, rx) = std::sync::mpsc::sync_channel(1024);
    let failed_repacks = AtomicU32::new(0);
    let start = std::time::Instant::now();

    let result = std::thread::scope(|s| {
        let failed_repacks = &failed_repacks;
        let pending_files = &pending_files;
        let writer = &mut writer;
        let pb_serialize = &pb_serialize;
        let pb_write = &pb_write;
        let mpb = &mpb;

        let mut handles = Vec::new();

        for _ in 0..thread_count {
            let tx = tx.clone();

            let handle = s.spawn(move || {
                loop {
                    let file = {
                        let mut lock = pending_files.lock().unwrap();

                        if let Some(file) = lock.pop() {
                            file
                        } else {
                            break;
                        }
                    };

                    let result: anyhow::Result<()> = (|| {
                        let reader = BufReader::new(File::open(&file)?);
                        let descriptor = serde_json::from_reader::<_, Value>(reader)?;
                        let result = crate::util::serialize_descriptor(type_registry, &descriptor)?;

                        tx.send(result).unwrap();

                        Ok(())
                    })();

                    match result {
                        Ok(()) => {},
                        Err(e) => {
                            failed_repacks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                            mpb.suspend(|| {
                                error!("Error occurred while repacking `{}`: {}", file.display(), e);
                            });
                        }
                    }

                    pb_serialize.inc(1);
                }
            });

            handles.push(handle);
        }

        drop(tx);

        let writer_handle = s.spawn(move || {
            while let Ok((guid, data)) = rx.recv() {
                match writer.write_resource(&guid, &data) {
                    Ok(()) => {},
                    Err(e) => {
                        failed_repacks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                        mpb.suspend(|| {
                            error!("Error occurred while writing `{}`: {}", guid.to_qualified_string(), e);
                        });
                    }
                }

                pb_write.inc(1);
            }
        });

        match writer_handle.join() {
            Ok(()) => {},
            Err(e) => {
                {
                    let mut lock = pending_files.lock().unwrap();
                    lock.clear();
                }

                for handle in handles {
                    handle.join().unwrap()
                }

                fatal!("Writer thread panicked: {:?}", e)
            }
        }

        for handle in handles {
            handle.join().unwrap()
        }

        Ok(())
    });

    pb_serialize.finish_and_clear();
    pb_write.finish_and_clear();

    match result {
        Ok(()) => {},
        Err(e) => {
            return Err(e);
        }
    }

    match writer.finalize() {
        Ok(()) => {},
        Err(e) => {
            return Err(Error(format!("Failed to write to {}: {}", file_path.display(), e)));
        }
    }

    let failed_repacks = failed_repacks.load(std::sync::atomic::Ordering::Relaxed);
    let end = std::time::Instant::now();

    info!("Repacked a total of {}/{} descriptors in {:?}", total - failed_repacks, total, end - start);

    Ok(())
}

fn repack_stdin(
    game_dir: &Path,
    file_name: Option<&str>,
    ref_kfc_file: &mut KFCFile,
    type_registry: &TypeRegistry,
    thread_count: u8
) -> Result<(), Error> {
    let file_name = get_file_name(game_dir, file_name)?;
    let file_path = get_file(game_dir, Some(&file_name), "kfc")?;

    let mut writer = match KFCWriter::new_incremental(
        game_dir,
        &file_name,
        ref_kfc_file,
        type_registry
    ) {
        Ok(writer) => writer,
        Err(e) => fatal!("Failed to open {}: {}", file_path.display(), e)
    };

    let (tx_in, rx_in) = crossbeam_channel::unbounded::<(usize, String)>();
    let (tx, rx) = std::sync::mpsc::sync_channel(1024);
    let failed_repacks = AtomicU32::new(0);
    let total = AtomicU32::new(0);
    let start = std::time::Instant::now();

    let result = std::thread::scope(|s| {
        let failed_repacks = &failed_repacks;
        let writer = &mut writer;
        let total = &total;

        let mut handles = Vec::new();

        for _ in 0..thread_count {
            let tx = tx.clone();
            let rx_in = rx_in.clone();

            let handle = s.spawn(move || {
                for (i, descriptor_str) in rx_in.iter() {
                    let descriptor = match serde_json::from_str::<Value>(&descriptor_str) {
                        Ok(d) => d,
                        Err(e) => {
                            failed_repacks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            error!("Error occurred while parsing descriptor {}: {}", i, e);
                            continue;
                        }
                    };

                    let result = match crate::util::serialize_descriptor(type_registry, &descriptor) {
                        Ok(result) => result,
                        Err(e) => {
                            failed_repacks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            error!("Error occurred while serializing descriptor {}: {}", i, e);
                            continue;
                        }
                    };

                    tx.send(result).unwrap();
                }
            });

            handles.push(handle);
        }

        drop(tx);
        drop(rx_in);

        let in_handle = s.spawn(move || {
            let stdin = std::io::stdin();

            for (i, line) in stdin.lines().enumerate() {
                let line = match line {
                    Ok(line) => line,
                    Err(e) => {
                        error!("Error occurred while reading from stdin: {}", e);
                        break;
                    }
                };

                if line.is_empty() {
                    continue;
                }

                let result = tx_in.send((i, line));

                total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                if result.is_err() {
                    break;
                }
            }
        });

        let writer_handle = s.spawn(move || {
            while let Ok((guid, data)) = rx.recv() {
                match writer.write_resource(&guid, &data) {
                    Ok(()) => {},
                    Err(e) => {
                        failed_repacks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        error!("Error occurred while writing `{}`: {}", guid.to_qualified_string(), e);
                    }
                }
            }
        });

        match writer_handle.join() {
            Ok(()) => {},
            Err(e) => {
                fatal!("Writer thread panicked: {:?}", e)
            }
        }

        match in_handle.join() {
            Ok(()) => {},
            Err(e) => {
                fatal!("Stdin reader thread panicked: {:?}", e)
            }
        }

        for handle in handles {
            handle.join().unwrap()
        }

        Ok(())
    });

    match result {
        Ok(()) => {},
        Err(e) => {
            return Err(e);
        }
    }

    match writer.finalize() {
        Ok(()) => {},
        Err(e) => {
            return Err(Error(format!("Failed to write to {}: {}", file_path.display(), e)));
        }
    }

    let total = total.load(std::sync::atomic::Ordering::Relaxed);
    let failed_repacks = failed_repacks.load(std::sync::atomic::Ordering::Relaxed);
    let end = std::time::Instant::now();

    info!("Repacked a total of {}/{} descriptors in {:?}", total - failed_repacks, total, end - start);

    Ok(())
}

fn revert_repack(
    game_dir: &Path,
    file_name: Option<&str>,
    because_of_error: bool,
) -> Result<(), Error> {
    let kfc_file = get_file(game_dir, file_name, "kfc")?;
    let kfc_file_bak = get_file(game_dir, file_name, "kfc.bak")?;

    if because_of_error {
        error!("An error occurred during repack, reverting changes...");
    } else {
        info!("Reverting repack...");
    }

    match std::fs::copy(&kfc_file_bak, &kfc_file) {
        Ok(_) => {},
        Err(e) => {
            error!("Failed to revert repack: {}", e);

            if kfc_file_bak.exists() {
                fatal!("Please manually restore from backup file: {}", kfc_file_bak.display());
            } else {
                fatal!("Backup file is missing, please verify integrity of the game files");
            }
        }
    }

    info!("Reverted repack successfully");

    Ok(())
}

fn extract_types(
    game_dir: &Path,
    file_name: Option<&str>,
) -> Result<(), Error> {
    let executable = get_file(game_dir, file_name, "exe")?;
    let mut type_registry = match TypeRegistry::load_from_executable(executable) {
        Ok(count) => count,
        Err(e) => {
            fatal!("Failed to extract types: {}", e)
        }
    };

    info!("Extracted a total of {} types", type_registry.len());

    let file_name = get_file(game_dir, file_name, "kfc")?;
    let version_tag = match KFCFile::get_version_tag(&file_name) {
        Ok(file) => file,
        Err(e) => fatal!("Failed to read {}: {}", file_name.display(), e)
    };

    type_registry.version = version_tag;

    let path = current_exe().unwrap()
        .parent().unwrap()
        .join("reflection_data.json");

    match dump_types_to_path(&type_registry, path, false) {
        Ok(_) => {},
        Err(e) => {
            fatal!("Failed to dump reflection data: {}", e)
        }
    }

    info!("Reflection data has been written to reflection_data.json");

    Ok(())
}

fn load_type_registry(
    game_dir: Option<&Path>,
    file_name: Option<&str>,
    retry: bool
) -> Result<TypeRegistry, Error> {
    let flag = AtomicBool::new(false);
    let pb = ProgressBar::no_length();

    pb.set_style(ProgressStyle::with_template(
        &format!("{} {{spinner:.green}} {{msg}}", "info:".blue().bold())
    ).unwrap());
    pb.set_message("Loading reflection data...");

    let result = std::thread::scope(|s| {
        let progress_handle = s.spawn(|| {
            while !flag.load(std::sync::atomic::Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(50));
                pb.tick();
            }
        });

        let loading_handle = s.spawn(|| {
            load_types_from_path(
                current_exe().unwrap()
                    .parent().unwrap()
                    .join("reflection_data.json")
                    .as_path()
            )
        });

        // Wait for the loading to finish and just unwrap potential panic
        let result = loading_handle.join().unwrap();

        flag.store(true, std::sync::atomic::Ordering::Relaxed);
        progress_handle.join().unwrap();

        result
    });

    pb.finish_and_clear();

    let type_registry = match result {
        Ok(type_registry) => {
            if let Some(game_dir) = game_dir {
                let kfc_path = get_file(game_dir, file_name, "kfc")?;
                let version_tag = match KFCFile::get_version_tag(&kfc_path) {
                    Ok(file) => file,
                    Err(e) => fatal!("Failed to read {}: {}", kfc_path.display(), e)
                };

                if type_registry.version != version_tag {
                    if retry {
                        warn!("reflection_data.json is outdated, attempting to extract types again...");
                        extract_types(game_dir, file_name)?;
                        return load_type_registry(Some(game_dir), file_name, false);
                    }

                    fatal!("reflection_data.json is outdated, please extract types again");
                }
            }

            type_registry
        },
        Err(TypeParseError::Io(e)) => {
            if let Some(game_dir) = game_dir {
                if e.kind() == std::io::ErrorKind::NotFound && retry {
                    warn!("reflection_data.json not found, attempting to extract types first...");
                    extract_types(game_dir, file_name)?;
                    return load_type_registry(Some(game_dir), file_name, false);
                } else {
                    fatal!("Failed to load reflection_data.json: {}", e);
                }
            } else if e.kind() == std::io::ErrorKind::NotFound {
                fatal!("reflection_data.json not found, please extract types first");
            } else {
                fatal!("Failed to load reflection_data.json: {}", e);
            }
        }
        Err(TypeParseError::Json(e)) => {
            if let Some(game_dir) = game_dir {
                if retry {
                    warn!("reflection_data.json is invalid, attempting to extract types again...");
                    extract_types(game_dir, file_name)?;
                    return load_type_registry(Some(game_dir), file_name, false);
                }
            }

            fatal!("Failed to load reflection_data.json: {}", e)
        }
    };

    info!("Loaded a total of {} types", type_registry.len());

    Ok(type_registry)
}

fn assemble_impact(
    input_file: &Path,
    output_file: Option<&Path>,
    guid: Option<&str>,
) -> Result<(), Error> {
    let type_registry = load_type_registry(None, None, true)?;
    let file_name = input_file.file_stem().unwrap().to_str().unwrap();

    let guid_str = guid
        .or_else(|| output_file.map(|f| f.file_stem().unwrap().to_str().unwrap()))
        .unwrap_or(file_name);

    let guid = match ResourceId::parse_qualified(guid_str) {
        Some(guid) => guid,
        None => {
            if let Some(guid) = guid {
                fatal!("`{}` is not a valid descriptor guid", guid);
            } else if output_file.is_some() {
                fatal!("Output file name must be a valid descriptor guid");
            } else {
                fatal!("Input file name must be a valid descriptor guid");
            }
        }
    };

    // read files

    let impact_file = input_file.with_file_name(format!("{}.impact", file_name));
    let shutdown_file = input_file.with_file_name(format!("{}.shutdown.impact", file_name));
    let data_file = input_file.with_file_name(format!("{}.data.json", file_name));

    let impact_content = match std::fs::read_to_string(&impact_file) {
        Ok(content) => content,
        Err(e) => fatal!("Failed to read `{}.impact`: {}", file_name, e)
    };
    let shutdown_content = match std::fs::read_to_string(&shutdown_file) {
        Ok(content) => content,
        Err(e) => fatal!("Failed to read `{}.shutdown.impact`: {}", file_name, e)
    };
    let data_content = match std::fs::read_to_string(&data_file) {
        Ok(content) => content,
        Err(e) => fatal!("Failed to read `{}.data.json`: {}", file_name, e)
    };

    // parse data

    let program_data = match serde_json::from_str::<ImpactProgramData>(&data_content) {
        Ok(data) => data,
        Err(e) => fatal!("Failed to parse `{}.data.json`: {}", file_name, e)
    };

    // assemble bytecode

    let assembler = ImpactAssembler::new(&type_registry);

    let impact_ops = match assembler.parse_text(&program_data, &impact_content) {
        Ok(ops) => ops,
        Err(e) => fatal!("Failed to parse `{}.impact`: {}", file_name, e)
    };

    let shutdown_ops = match assembler.parse_text(&program_data, &shutdown_content) {
        Ok(ops) => ops,
        Err(e) => fatal!("Failed to parse `{}.shutdown.impact`: {}", file_name, e)
    };

    // create program

    let impact_program = match program_data.into_program(
        &type_registry,
        guid.guid().into(),
        ImpactAssembler::assemble(&impact_ops),
        ImpactAssembler::assemble(&shutdown_ops),
    ) {
        Ok(program) => program,
        Err(e) => fatal!("Failed to create program: {}", e)
    };

    // info

    info!("Impact program info:");
    info!(" - {} + {} ops", impact_ops.len(), shutdown_ops.len());
    info!(" - {} data entries ({} bytes)", impact_program.data_layout.len(), impact_program.data.len());

    // write to file

    let output_file = output_file.unwrap_or(input_file)
        .with_extension("json");

    let writer = match File::create(&output_file) {
        Ok(file) => BufWriter::new(file),
        Err(e) => fatal!("Failed to create output file: {}", e)
    };

    match serde_json::to_writer_pretty(writer, &impact_program) {
        Ok(()) => {},
        Err(e) => fatal!("Failed to write to output file: {}", e)
    }

    info!("Impact program has been written to {}", output_file.display());

    Ok(())
}

fn disassemble_impact(
    input_file: &Path,
    output_file: Option<&Path>,
) -> Result<(), Error> {
    let type_registry = load_type_registry(None, None, true)?;
    let output_file = output_file.unwrap_or(input_file);
    let file_name = output_file.file_stem().unwrap().to_str().unwrap();

    let impact_file = output_file.with_file_name(format!("{}.impact", file_name));
    let shutdown_file = output_file.with_file_name(format!("{}.shutdown.impact", file_name));
    let data_file = output_file.with_file_name(format!("{}.data.json", file_name));

    // read program

    let reader = match File::open(input_file) {
        Ok(file) => BufReader::new(file),
        Err(e) => fatal!("Failed to open input file: {}", e)
    };

    let impact_program = match serde_json::from_reader::<_, ImpactProgram>(reader) {
        Ok(program) => program,
        Err(e) => fatal!("Failed to parse input file: {}", e)
    };

    // extract and write data

    let impact_data = match ImpactProgramData::from_program(&type_registry, &impact_program) {
        Ok(data) => data,
        Err(e) => fatal!("Failed to parse data from program: {}", e)
    };

    let data_writer = match File::create(&data_file) {
        Ok(file) => BufWriter::new(file),
        Err(e) => fatal!("Failed to create `{}.data.json`: {}", file_name, e)
    };

    match serde_json::to_writer_pretty(data_writer, &impact_data) {
        Ok(()) => {},
        Err(e) => fatal!("Failed to write `{}.data.json`: {}", file_name, e)
    }

    // disassemble bytecode

    let assembler = ImpactAssembler::new(&type_registry);

    let mut impact_file_writer = match File::create(&impact_file) {
        Ok(file) => BufWriter::new(file),
        Err(e) => fatal!("Failed to create `{}.impact`: {}", file_name, e)
    };

    if let Err(e) =  assembler.write_text(
        &mut impact_file_writer,
        &impact_program,
        &ImpactAssembler::disassemble(&impact_program.code),
    ) {
        fatal!("Failed to write `{}.impact`: {}", file_name, e);
    }

    let mut shutdown_file_writer = match File::create(&shutdown_file) {
        Ok(file) => BufWriter::new(file),
        Err(e) => fatal!("Failed to create `{}.shutdown.impact`: {}", file_name, e)
    };

    if let Err(e) = assembler.write_text(
        &mut shutdown_file_writer,
        &impact_program,
        &ImpactAssembler::disassemble(&impact_program.code_shutdown),
    ) {
        fatal!("Failed to write `{}.shutdown.impact`: {}", file_name, e);
    }

    // info

    info!("Impact program has been written to:");
    info!(" - {}", impact_file.display());
    info!(" - {}", shutdown_file.display());
    info!(" - {}", data_file.display());

    Ok(())
}

fn extract_nodes() -> Result<(), Error> {
    let type_registry = load_type_registry(None, None, true)?;
    let nodes = type_registry.get_impact_nodes()
        .into_values()
        .collect::<Vec<_>>();

    let output_path = current_exe().unwrap()
        .parent().unwrap()
        .join("impact_nodes.json");

    let writer = match File::create(&output_path) {
        Ok(file) => BufWriter::new(file),
        Err(e) => fatal!("Failed to create `impact_nodes.json`: {}", e),
    };

    match serde_json::to_writer_pretty(writer, &nodes) {
        Ok(()) => {},
        Err(e) => fatal!("Failed to write `impact_nodes.json`: {}", e)
    }

    info!("Impact node data has been written to {}", std::path::absolute(output_path).unwrap().display());

    Ok(())
}

fn get_file(
    game_dir: &Path,
    file_name: Option<&str>,
    extension: &str
) -> Result<PathBuf, Error> {
    let file_name = get_file_name(game_dir, file_name)?;
    let file = game_dir.join(format!("{}.{}", file_name, extension));

    if !file.exists() {
        fatal!("File not found: {}", file.display());
    }

    Ok(file)
}

fn get_file_opt(
    game_dir: &Path,
    file_name: Option<&str>,
    extension: &str
) -> Result<PathBuf, Error> {
    let file_name = get_file_name(game_dir, file_name)?;
    let file = game_dir.join(format!("{}.{}", file_name, extension));

    Ok(file)
}

fn get_file_name(
    game_dir: &Path,
    file_name: Option<&str>
) -> Result<String, Error> {
    if let Some(file_name) = file_name {
        Ok(file_name.into())
    } else if game_dir.join("enshrouded.kfc").exists() || game_dir.join("enshrouded.exe").exists() {
        Ok("enshrouded".into())
    } else if game_dir.join("enshrouded_server.kfc").exists() || game_dir.join("enshrouded_server.exe").exists() {
        Ok("enshrouded_server".into())
    } else {
        // try to find file with .kfc or .exe extension
        for file in std::fs::read_dir(game_dir).into_iter().flatten().flatten() {
            if let Some(ext) = file.path().extension() {
                if ext == "kfc" || ext == "exe" {
                    let file = file.path();
                    let file_name = file.file_stem()
                        .and_then(|s| s.to_str());

                    if let Some(file_name) = file_name {
                        return Ok(file_name.into());
                    }
                }
            }
        }

        fatal!("Unable to find the kfc/exe file in game directory, please specify it with --file_name");
    }
}

fn load_types_from_path(
    path: impl AsRef<Path>
) -> Result<TypeRegistry, TypeParseError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let json = serde_json::from_reader::<_, TypeRegistry>(reader)?;

    Ok(json)
}

fn dump_types_to_path(
    type_registry: &TypeRegistry,
    path: impl AsRef<Path>,
    pretty: bool
) -> Result<(), TypeParseError> {
    let file = File::create(path)?;
    let writer = BufWriter::new(file);

    if pretty {
        serde_json::to_writer_pretty(writer, type_registry)?;
    } else {
        serde_json::to_writer(writer, &type_registry)?;
    }

    Ok(())
}

/// Content metadata extracted from resources
#[derive(Debug, Clone)]
enum ContentMetadata {
    Image {
        width: u32,
        height: u32,
        format: PixelFormat,
        level_count: u32,
        debug_name: Option<String>,
    },
    Audio {
        channels: u16,
        sample_rate: u32,
        frame_count: u32,
        debug_name: Option<String>,
    },
}

/// Extract ContentHash from a data object with size, hash0, hash1, hash2 fields
fn extract_content_hash_from_data(data_obj: &indexmap::IndexMap<String, Value>) -> Option<ContentHash> {
    let size = data_obj.get("size")?.as_u64()? as u32;
    let hash0 = data_obj.get("hash0")?.as_u64()? as u32;
    let hash1 = data_obj.get("hash1")?.as_u64()? as u32;
    let hash2 = data_obj.get("hash2")?.as_u64()? as u32;

    // Construct ContentHash directly from the values
    Some(ContentHash::new(size, hash0, hash1, hash2))
}

/// Extract image metadata from a texture object (handles nested structures)
fn extract_image_metadata(texture_obj: &indexmap::IndexMap<String, Value>) -> Option<(u32, u32, PixelFormat, u32)> {
    // Try direct width/height fields first
    let width = texture_obj.get("width").and_then(|v| v.as_u64()).map(|v| v as u32);
    let height = texture_obj.get("height").and_then(|v| v.as_u64()).map(|v| v as u32);

    // Try nested size.x/size.y structure
    let (w, h) = if let (Some(w), Some(h)) = (width, height) {
        (Some(w), Some(h))
    } else if let Some(Value::Struct(size_obj)) = texture_obj.get("size") {
        let w = size_obj.get("x").and_then(|v| v.as_u64()).map(|v| v as u32);
        let h = size_obj.get("y").and_then(|v| v.as_u64()).map(|v| v as u32);
        (w, h)
    } else {
        (None, None)
    };

    let format = texture_obj.get("format").and_then(|v| v.as_u64()).map(|v| v as u32);
    let level_count = texture_obj.get("levelCount")
        .or_else(|| texture_obj.get("level_count"))
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .unwrap_or(1);

    if let (Some(w), Some(h), Some(f)) = (w, h, format) {
        if w > 0 && h > 0 {
            if let Some(pixel_format) = pixel_format_from_u32(f) {
                return Some((w, h, pixel_format, level_count));
            }
        }
    }

    None
}

/// Recursively scan a Value for ContentHash fields and extract associated metadata
fn scan_value_for_content(
    value: &Value,
    parent_struct: Option<&indexmap::IndexMap<String, Value>>,
    content_map: &mut HashMap<ContentHash, ContentMetadata>,
    item_debug_names: Option<&HashMap<Guid, String>>,
) {
    match value {
        Value::Guid(guid) => {
            // Check if this is a ContentHash (not None)
            let content_hash = ContentHash::from_guid(*guid);
            if !content_hash.is_none() {
                // Check if parent has image/audio metadata
                if let Some(parent) = parent_struct {
                    // Try to extract image metadata from parent
                    if let Some((w, h, fmt, level_count)) = extract_image_metadata(parent) {
                        let debug_name = parent.get("debugName")
                            .or_else(|| parent.get("debug_name"))
                            .and_then(|v| v.as_string())
                            .map(|s| s.clone());

                        content_map.insert(content_hash, ContentMetadata::Image {
                            width: w,
                            height: h,
                            format: fmt,
                            level_count,
                            debug_name,
                        });
                        return;
                    }

                    // Try to extract audio metadata
                    let channels = parent.get("channels")
                        .or_else(|| parent.get("channelCount"))
                        .and_then(|v| v.as_u64())
                        .map(|v| v as u16);
                    let sample_rate = parent.get("sampleRate")
                        .or_else(|| parent.get("sample_rate"))
                        .and_then(|v| v.as_u64())
                        .map(|v| v as u32);
                    let frame_count = parent.get("frameCount")
                        .or_else(|| parent.get("frame_count"))
                        .or_else(|| parent.get("sampleCount"))
                        .and_then(|v| v.as_u64())
                        .map(|v| v as u32);
                    let debug_name = parent.get("debugName")
                        .or_else(|| parent.get("debug_name"))
                        .and_then(|v| v.as_string())
                        .map(|s| s.clone());

                    if let (Some(ch), Some(sr), Some(fc)) = (channels, sample_rate, frame_count) {
                        if ch > 0 && sr > 0 && fc > 0 {
                            content_map.insert(content_hash, ContentMetadata::Audio {
                                channels: ch,
                                sample_rate: sr,
                                frame_count: fc,
                                debug_name,
                            });
                            return;
                        }
                    }
                }
            }
        }
        Value::Struct(fields) => {
            // Check for nested texture structures
            // ItemIconRegistry uses "uiTexture", BuffType uses "icon.texture"
            let texture_field = fields.get("uiTexture")
                .or_else(|| fields.get("icon").and_then(|icon| {
                    if let Value::Struct(icon_struct) = icon {
                        icon_struct.get("texture")
                    } else {
                        None
                    }
                }));

            if let Some(Value::Struct(texture_struct)) = texture_field {
                // Extract image metadata from texture
                if let Some((w, h, fmt, level_count)) = extract_image_metadata(texture_struct) {
                    // Look for ContentHash in texture.data
                    if let Some(Value::Struct(data_obj)) = texture_struct.get("data") {
                        if let Some(content_hash) = extract_content_hash_from_data(data_obj) {
                            // Get debug name: prioritize lookup by icon guid in item_debug_names
                            // This is the correct way for icon registries - icon.guid maps to ItemInfo.objectId
                            let mut debug_name = None;

                            // First, try to look up by icon's guid or resource's $guid
                            // ItemIconRegistry icons have "guid", BuffType/etc have "$guid"
                            if let Some(item_guids) = item_debug_names {
                                if let Some(Value::Guid(icon_guid)) = fields.get("guid").or_else(|| fields.get("$guid")) {
                                    debug_name = item_guids.get(icon_guid).cloned();
                                }
                            }

                            // Fallback to direct debug name fields if lookup didn't work
                            if debug_name.is_none() {
                                debug_name = fields.get("debugName")
                                    .or_else(|| fields.get("debug_name"))
                                    .or_else(|| texture_struct.get("debugName"))
                                    .or_else(|| texture_struct.get("debug_name"))
                                    .and_then(|v| v.as_string())
                                    .map(|s| s.clone());
                            }

                            content_map.insert(content_hash, ContentMetadata::Image {
                                width: w,
                                height: h,
                                format: fmt,
                                level_count,
                                debug_name: debug_name.clone(),
                            });
                        }
                    }
                }
            }

            // Also check for icons array (ItemIconRegistryResource structure)
            if let Some(Value::Array(icons)) = fields.get("icons") {
                // Process each icon in the registry
                for icon in icons {
                    if let Value::Struct(icon_fields) = icon {
                        // Recursively process this icon (which will handle uiTexture)
                        scan_value_for_content(icon, Some(icon_fields), content_map, item_debug_names);
                    }
                }
            }

            // Check for data object with ContentHash fields
            if let Some(Value::Struct(data_obj)) = fields.get("data") {
                if let Some(content_hash) = extract_content_hash_from_data(data_obj) {
                    // Try to find metadata in parent or sibling fields
                    if let Some(parent) = parent_struct {
                        if let Some((w, h, fmt, level_count)) = extract_image_metadata(parent) {
                            let debug_name = parent.get("debugName")
                                .or_else(|| parent.get("debug_name"))
                                .and_then(|v| v.as_string())
                                .map(|s| s.clone());

                            // Only insert if not already present (to avoid overwriting entries with debug names)
                            content_map.entry(content_hash).or_insert(ContentMetadata::Image {
                                width: w,
                                height: h,
                                format: fmt,
                                level_count,
                                debug_name,
                            });
                        }
                    }

                    // Also check if the parent of this struct has the metadata
                    if let Some((w, h, fmt, level_count)) = extract_image_metadata(fields) {
                        let debug_name = fields.get("debugName")
                            .or_else(|| fields.get("debug_name"))
                            .and_then(|v| v.as_string())
                            .map(|s| s.clone());

                        // Only insert if not already present (to avoid overwriting entries with debug names)
                        content_map.entry(content_hash).or_insert(ContentMetadata::Image {
                            width: w,
                            height: h,
                            format: fmt,
                            level_count,
                            debug_name,
                        });
                    }
                }
            }

            // Scan each field recursively
            for (_, field_value) in fields.iter() {
                scan_value_for_content(field_value, Some(fields), content_map, item_debug_names);
            }
        }
        Value::Array(items) => {
            for item in items {
                scan_value_for_content(item, None, content_map, item_debug_names);
            }
        }
        Value::Variant(variant) => {
            for (_, field_value) in variant.value.iter() {
                scan_value_for_content(field_value, Some(&variant.value), content_map, item_debug_names);
            }
        }
        _ => {}
    }
}

/// Convert u32 to PixelFormat enum
fn pixel_format_from_u32(value: u32) -> Option<PixelFormat> {
    // The PixelFormat enum values correspond to their ordinal position
    // This is a simplified approach - in practice we'd need the exact mapping
    let formats = [
        PixelFormat::None,
        PixelFormat::R4G4_unorm_pack8,
        PixelFormat::R4G4B4A4_unorm_pack16,
        PixelFormat::B4G4R4A4_unorm_pack16,
        PixelFormat::R5G6B5_unorm_pack16,
        PixelFormat::B5G6R5_unorm_pack16,
        PixelFormat::R5G5B5A1_unorm_pack16,
        PixelFormat::B5G5R5A1_unorm_pack16,
        PixelFormat::A1R5G5B5_unorm_pack16,
        PixelFormat::R8_unorm,
        PixelFormat::R8_snorm,
        PixelFormat::R8_uscaled,
        PixelFormat::R8_sscaled,
        PixelFormat::R8_uint,
        PixelFormat::R8_sint,
        PixelFormat::R8_srgb,
        PixelFormat::R8G8_unorm,
        PixelFormat::R8G8_snorm,
        PixelFormat::R8G8_uscaled,
        PixelFormat::R8G8_sscaled,
        PixelFormat::R8G8_uint,
        PixelFormat::R8G8_sint,
        PixelFormat::R8G8_srgb,
        PixelFormat::R8G8B8_unorm,
        PixelFormat::R8G8B8_snorm,
        PixelFormat::R8G8B8_uscaled,
        PixelFormat::R8G8B8_sscaled,
        PixelFormat::R8G8B8_uint,
        PixelFormat::R8G8B8_sint,
        PixelFormat::R8G8B8_srgb,
        PixelFormat::B8G8R8_unorm,
        PixelFormat::B8G8R8_snorm,
        PixelFormat::B8G8R8_uscaled,
        PixelFormat::B8G8R8_sscaled,
        PixelFormat::B8G8R8_uint,
        PixelFormat::B8G8R8_sint,
        PixelFormat::B8G8R8_srgb,
        PixelFormat::R8G8B8A8_unorm,
        PixelFormat::R8G8B8A8_snorm,
        PixelFormat::R8G8B8A8_uscaled,
        PixelFormat::R8G8B8A8_sscaled,
        PixelFormat::R8G8B8A8_uint,
        PixelFormat::R8G8B8A8_sint,
        PixelFormat::R8G8B8A8_srgb,
        PixelFormat::B8G8R8A8_unorm,
        PixelFormat::B8G8R8A8_snorm,
        PixelFormat::B8G8R8A8_uscaled,
        PixelFormat::B8G8R8A8_sscaled,
        PixelFormat::B8G8R8A8_uint,
        PixelFormat::B8G8R8A8_sint,
        PixelFormat::B8G8R8A8_srgb,
        PixelFormat::A8B8G8R8_unorm_pack32,
        PixelFormat::A8B8G8R8_snorm_pack32,
        PixelFormat::A8B8G8R8_uscaled_pack32,
        PixelFormat::A8B8G8R8_sscaled_pack32,
        PixelFormat::A8B8G8R8_uint_pack32,
        PixelFormat::A8B8G8R8_sint_pack32,
        PixelFormat::A8B8G8R8_srgb_pack32,
        PixelFormat::A2R10G10B10_unorm_pack32,
        PixelFormat::A2R10G10B10_snorm_pack32,
        PixelFormat::A2R10G10B10_uscaled_pack32,
        PixelFormat::A2R10G10B10_sscaled_pack32,
        PixelFormat::A2R10G10B10_uint_pack32,
        PixelFormat::A2R10G10B10_sint_pack32,
        PixelFormat::A2B10G10R10_unorm_pack32,
        PixelFormat::A2B10G10R10_snorm_pack32,
        PixelFormat::A2B10G10R10_uscaled_pack32,
        PixelFormat::A2B10G10R10_sscaled_pack32,
        PixelFormat::A2B10G10R10_uint_pack32,
        PixelFormat::A2B10G10R10_sint_pack32,
        PixelFormat::R16_unorm,
        PixelFormat::R16_snorm,
        PixelFormat::R16_uscaled,
        PixelFormat::R16_sscaled,
        PixelFormat::R16_uint,
        PixelFormat::R16_sint,
        PixelFormat::R16_sfloat,
        PixelFormat::R16G16_unorm,
        PixelFormat::R16G16_snorm,
        PixelFormat::R16G16_uscaled,
        PixelFormat::R16G16_sscaled,
        PixelFormat::R16G16_uint,
        PixelFormat::R16G16_sint,
        PixelFormat::R16G16_sfloat,
        PixelFormat::R16G16B16_unorm,
        PixelFormat::R16G16B16_snorm,
        PixelFormat::R16G16B16_uscaled,
        PixelFormat::R16G16B16_sscaled,
        PixelFormat::R16G16B16_uint,
        PixelFormat::R16G16B16_sint,
        PixelFormat::R16G16B16_sfloat,
        PixelFormat::R16G16B16A16_unorm,
        PixelFormat::R16G16B16A16_snorm,
        PixelFormat::R16G16B16A16_uscaled,
        PixelFormat::R16G16B16A16_sscaled,
        PixelFormat::R16G16B16A16_uint,
        PixelFormat::R16G16B16A16_sint,
        PixelFormat::R16G16B16A16_sfloat,
        PixelFormat::R32_uint,
        PixelFormat::R32_sint,
        PixelFormat::R32_sfloat,
        PixelFormat::R32G32_uint,
        PixelFormat::R32G32_sint,
        PixelFormat::R32G32_sfloat,
        PixelFormat::R32G32B32_uint,
        PixelFormat::R32G32B32_sint,
        PixelFormat::R32G32B32_sfloat,
        PixelFormat::R32G32B32A32_uint,
        PixelFormat::R32G32B32A32_sint,
        PixelFormat::R32G32B32A32_sfloat,
        PixelFormat::R64_uint,
        PixelFormat::R64_sint,
        PixelFormat::R64_sfloat,
        PixelFormat::R64G64_uint,
        PixelFormat::R64G64_sint,
        PixelFormat::R64G64_sfloat,
        PixelFormat::R64G64B64_uint,
        PixelFormat::R64G64B64_sint,
        PixelFormat::R64G64B64_sfloat,
        PixelFormat::R64G64B64A64_uint,
        PixelFormat::R64G64B64A64_sint,
        PixelFormat::R64G64B64A64_sfloat,
        PixelFormat::B10G11R11_ufloat_pack32,
        PixelFormat::E5B9G9R9_ufloat_pack32,
        PixelFormat::D16_unorm,
        PixelFormat::X8_D24_unorm_pack32,
        PixelFormat::D32_sfloat,
        PixelFormat::S8_uint,
        PixelFormat::D16_unorm_S8_uint,
        PixelFormat::D24_unorm_S8_uint,
        PixelFormat::D32_sfloat_S8_uint,
        PixelFormat::BC1_RGB_unorm_block,
        PixelFormat::BC1_RGB_srgb_block,
        PixelFormat::BC1_RGBA_unorm_block,
        PixelFormat::BC1_RGBA_srgb_block,
        PixelFormat::BC2_unorm_block,
        PixelFormat::BC2_srgb_block,
        PixelFormat::BC3_unorm_block,
        PixelFormat::BC3_srgb_block,
        PixelFormat::BC4_unorm_block,
        PixelFormat::BC4_snorm_block,
        PixelFormat::BC5_unorm_block,
        PixelFormat::BC5_snorm_block,
        PixelFormat::BC6H_ufloat_block,
        PixelFormat::BC6H_sfloat_block,
        PixelFormat::BC7_unorm_block,
        PixelFormat::BC7_srgb_block,
    ];

    formats.get(value as usize).copied()
}

/// Extract texture metadata from ItemIconRegistryResource
/// This is a simplified version that relies on the existing scan_value_for_content
/// The registry flag will be used to filter which resources to scan
fn extract_registry_metadata(
    kfc_reader: &KFCReader,
    type_registry: &TypeRegistry,
    registry_type: &str,
    content_map: &mut HashMap<ContentHash, ContentMetadata>,
    item_debug_names: Option<&HashMap<Guid, String>>,
) -> anyhow::Result<()> {
    let file = kfc_reader.file();
    let mut cursor = kfc_reader.new_cursor()?;

    // For now, we'll use the existing scan approach but filter by registry type
    // A more optimized version would directly parse ItemIconRegistryResource
    // but that requires knowing the exact type structure
    for resource_id in file.resources().keys() {
        let type_meta = match type_registry.get_by_hash(LookupKey::Qualified(resource_id.type_hash())) {
            Some(meta) => meta,
            None => continue,
        };

        // Filter by registry type if specified
        if registry_type != "all" {
            let type_name = &type_meta.name;
            match registry_type {
                "icons" => {
                    if !type_name.contains("Icon") && !type_name.contains("icon") {
                        continue;
                    }
                }
                "ui" => {
                    if !type_name.contains("UI") && !type_name.contains("Ui") && !type_name.contains("ui") {
                        continue;
                    }
                }
                _ => {}
            }
        }

        let mut data = Vec::new();
        if !cursor.read_resource_into(resource_id, &mut data)? {
            continue;
        }

        if let Ok(value) = Value::from_bytes(type_registry, type_meta, &data) {
            scan_value_for_content(&value, None, content_map, item_debug_names);
        }
    }

    Ok(())
}

/// Generate filename with optional debug name
fn generate_filename(
    hash: &ContentHash,
    extension: &str,
    debug_name: Option<&str>,
    use_debug_names: bool,
) -> String {
    // Remove leading dot from extension if present (extension should be like "png" or ".png")
    let ext = extension.strip_prefix('.').unwrap_or(extension);

    if use_debug_names {
        if let Some(name) = debug_name {
            // Sanitize debug name for filesystem
            let sanitized: String = name
                .chars()
                .map(|c| match c {
                    '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
                    c if c.is_control() => '_',
                    c => c,
                })
                .collect();

            format!("{}_{}.{}", sanitized, hash, ext)
        } else {
            format!("{}.{}", hash, ext)
        }
    } else {
        format!("{}.{}", hash, ext)
    }
}

/// Get output directory path based on content type and organize flag
fn get_output_path(
    base_dir: &Path,
    organize: bool,
    content_type: &str,
    filename: &str,
) -> PathBuf {
    if organize && !content_type.is_empty() {
        base_dir.join(content_type).join(filename)
    } else {
        base_dir.join(filename)
    }
}

fn extract_content(
    game_dir: &Path,
    file_name: Option<&str>,
    output_dir: &Path,
    filter: String,
    convert: bool,
    organize: bool,
    use_debug_names: bool,
    mipmaps: bool,
    registry: Option<&str>,
    thread_count: u8,
    limit: Option<usize>,
) -> Result<(), Error> {
    if !game_dir.exists() {
        fatal!("Game directory does not exist: {}", game_dir.display());
    }

    if !output_dir.exists() {
        if let Err(e) = std::fs::create_dir_all(output_dir) {
            fatal!("Failed to create output directory: {}", e);
        }
    }

    let file_name_str = get_file_name(game_dir, file_name)?;
    let file_path = get_file(game_dir, Some(&file_name_str), "kfc")?;

    let file = match KFCFile::from_path(&file_path, false) {
        Ok(dir) => dir,
        Err(e) => fatal!("Failed to read {}: {}", file_path.display(), e)
    };

    enum Filter {
        All,
        ByHash(ContentHash)
    }

    let mut filters = Vec::new();

    for filter in filter.split(',') {
        let entry = filter.trim();

        if entry.is_empty() {
            continue;
        }

        if entry == "*" {
            filters.clear();
            filters.push(Filter::All);
            break;
        } else {
            match ContentHash::parse(entry) {
                Some(hash) => filters.push(Filter::ByHash(hash)),
                None => fatal!("`{}` is not a valid content hash", entry),
            }
        }
    }

    let mut hashes = HashSet::new();

    for filter in &filters {
        match filter {
            Filter::All => {
                hashes = file.contents().keys().iter().cloned().collect();
                break;
            }
            Filter::ByHash(hash) => {
                if file.contents().contains_key(hash) {
                    hashes.insert(*hash);
                } else {
                    fatal!("Content hash not found: {}", hash);
                }
            }
        }
    }

    // Build content metadata map if conversion is requested
    let content_metadata: HashMap<ContentHash, ContentMetadata> = if convert {
        let type_registry = match load_type_registry(Some(game_dir), file_name, true) {
            Ok(reg) => reg,
            Err(e) => {
                warn!("Failed to load type registry, conversion will be limited: {}", e);
                TypeRegistry::default()
            }
        };

        let kfc_reader = match KFCReader::new(game_dir, &file_name_str) {
            Ok(reader) => reader,
            Err(e) => fatal!("Failed to open {}: {}", file_path.display(), e)
        };

        // Build a map of GUIDs to debug names from various resource types
        let item_debug_names: Option<HashMap<Guid, String>> = if use_debug_names {
            info!("Building debug name lookup from all resource types...");
            let mut debug_map = HashMap::new();
            let mut cursor = match kfc_reader.new_cursor() {
                Ok(c) => c,
                Err(_) => {
                    warn!("Failed to create cursor for debug name lookup");
                    kfc_reader.new_cursor().unwrap_or_else(|_| panic!("Cannot continue"))
                }
            };

            let mut item_count = 0;
            let mut buff_count = 0;
            let mut other_count = 0;

            // Scan all resources for debug names
            for resource_id in file.resources().keys() {
                let type_meta = match type_registry.get_by_hash(LookupKey::Qualified(resource_id.type_hash())) {
                    Some(meta) => meta,
                    None => continue,
                };

                let mut data = Vec::new();
                if !cursor.read_resource_into(resource_id, &mut data).unwrap_or(false) {
                    continue;
                }

                if let Ok(value) = Value::from_bytes(&type_registry, type_meta, &data) {
                    if let Value::Struct(fields) = &value {
                        // ItemInfo: Use debugName field
                        if type_meta.name.contains("ItemInfo") {
                            if let (Some(Value::Guid(guid)), Some(debug_name)) = (
                                fields.get("objectId").or_else(|| fields.get("guid")),
                                fields.get("debugName").or_else(|| fields.get("debug_name"))
                            ) {
                                if let Some(name) = debug_name.as_string() {
                                    debug_map.insert(*guid, name.clone());
                                    item_count += 1;
                                }
                            }
                        }
                        // BuffType: Use resource GUID from resource_id
                        else if type_meta.name.contains("BuffType") {
                            let resource_guid = resource_id.guid();
                            // Try to get a readable name from debugName if available
                            let name = fields.get("debugName")
                                .or_else(|| fields.get("debug_name"))
                                .and_then(|v| v.as_string())
                                .map(|s| s.clone())
                                .unwrap_or_else(|| format!("Buff_{}", resource_guid));
                            debug_map.insert(resource_guid, name);
                            buff_count += 1;
                        }
                        // Other resource types with icons (Achievement, MapMarker, etc.)
                        else if type_meta.name.contains("Achievement")
                            || type_meta.name.contains("MapMarker")
                            || type_meta.name.contains("Journal")
                            || type_meta.name.contains("Recipe") {
                            let resource_guid = resource_id.guid();
                            // Extract type name for prefix
                            let type_prefix = if type_meta.name.contains("Achievement") { "Achievement" }
                                else if type_meta.name.contains("MapMarker") { "MapMarker" }
                                else if type_meta.name.contains("Journal") { "Journal" }
                                else if type_meta.name.contains("Recipe") { "Recipe" }
                                else { "Resource" };

                            let name = fields.get("debugName")
                                .or_else(|| fields.get("debug_name"))
                                .and_then(|v| v.as_string())
                                .map(|s| s.clone())
                                .unwrap_or_else(|| format!("{}_{}", type_prefix, resource_guid));
                            debug_map.insert(resource_guid, name);
                            other_count += 1;
                        }
                    }
                }
            }
            info!("Found {} debug names ({} items, {} buffs, {} other)",
                debug_map.len(), item_count, buff_count, other_count);
            Some(debug_map)
        } else {
            None
        };

        let mut content_map = HashMap::new();

        // Use registry-based extraction if specified
        if let Some(registry_type) = registry {
            info!("Extracting metadata from {} registry...", registry_type);
            if let Err(e) = extract_registry_metadata(&kfc_reader, &type_registry, registry_type, &mut content_map, item_debug_names.as_ref()) {
                warn!("Registry extraction failed, falling back to full scan: {}", e);
                // Fall through to full scan
            } else {
                info!("Found metadata for {} content blobs from registry", content_map.len());
            }
        }

        // If no registry specified or registry extraction didn't find everything, do full scan
        if registry.is_none() || content_map.is_empty() {
            info!("Scanning all resources for content metadata...");

            let mut cursor = match kfc_reader.new_cursor() {
                Ok(c) => c,
                Err(e) => fatal!("Failed to create cursor: {}", e)
            };

            // Scan all resources for content references
            let resource_keys: Vec<_> = file.resources().keys().iter().cloned().collect();
            let scan_pb = ProgressBar::new(resource_keys.len() as u64);
            scan_pb.set_style(ProgressStyle::default_bar()
                .template(&format!("{} Scanning... [{{bar:40}}] {{pos:>7}}/{{len:7}} {{msg}}", "info:".blue().bold()))
                .unwrap()
                .progress_chars("##-"));

            for resource_id in &resource_keys {
                let result: anyhow::Result<()> = (|| {
                    let mut data = Vec::new();
                    if !cursor.read_resource_into(resource_id, &mut data)? {
                        return Ok(());
                    }

                    let type_meta = type_registry.get_by_hash(LookupKey::Qualified(resource_id.type_hash()))
                        .ok_or_else(|| anyhow::anyhow!("Type not found"))?;
                    let value = Value::from_bytes(&type_registry, type_meta, &data)?;
                    scan_value_for_content(&value, None, &mut content_map, item_debug_names.as_ref());
                    Ok(())
                })();

                if let Err(e) = result {
                    // Silently skip resources that can't be parsed
                    let _ = e;
                }

                scan_pb.inc(1);
            }

            scan_pb.finish_and_clear();
        }

        info!("Found metadata for {} content blobs ({} images, {} audio)",
            content_map.len(),
            content_map.values().filter(|m| matches!(m, ContentMetadata::Image { .. })).count(),
            content_map.values().filter(|m| matches!(m, ContentMetadata::Audio { .. })).count()
        );

        content_map
    } else {
        HashMap::new()
    };

    // Filter hashes to only those with metadata when using registry
    if registry.is_some() && !content_metadata.is_empty() {
        let metadata_hashes: HashSet<ContentHash> = content_metadata.keys().cloned().collect();
        let original_count = hashes.len();
        hashes = hashes.intersection(&metadata_hashes).cloned().collect();
        info!("Filtered to {} content blobs with metadata (from {} total)", hashes.len(), original_count);
    }

    let kfc_reader = match KFCReader::new(game_dir, &file_name_str) {
        Ok(reader) => reader,
        Err(e) => fatal!("Failed to open {}: {}", file_path.display(), e)
    };

    let total_hashes = hashes.len();
    info!("Extracting {} content blobs{} to {}",
        if limit.is_some() { std::cmp::min(total_hashes, limit.unwrap()) } else { total_hashes },
        if let Some(l) = limit { format!(" (limited from {})", total_hashes) } else { String::new() },
        output_dir.display()
    );

    let pb = ProgressBar::new(if let Some(l) = limit { std::cmp::min(total_hashes, l) as u64 } else { total_hashes as u64 });
    pb.set_style(ProgressStyle::default_bar()
        .template(&format!("{} Extracting... [{{bar:40}}] {{pos:>7}}/{{len:7}} {{msg}}", "info:".blue().bold()))
        .unwrap()
        .progress_chars("##-"));

    // Apply limit if specified
    let hashes_to_extract: Vec<_> = if let Some(limit_count) = limit {
        hashes.into_iter().take(limit_count).collect()
    } else {
        hashes.into_iter().collect()
    };

    let total = hashes_to_extract.len() as u32;
    let pending_hashes = Mutex::new(hashes_to_extract);
    let failed_extracts = AtomicU32::new(0);
    let start = std::time::Instant::now();

    std::thread::scope(|s| {
        let mut handles = Vec::new();

        for i in 0..thread_count {
            let failed_extracts = &failed_extracts;
            let pending_hashes = &pending_hashes;
            let output_dir = &output_dir;
            let pb = &pb;
            let kfc_reader = &kfc_reader;
            let content_metadata = &content_metadata;
            let organize = organize;
            let use_debug_names = use_debug_names;
            let mipmaps = mipmaps;

            let handle = s.spawn(move || {
                let mut reader = match kfc_reader.new_cursor() {
                    Ok(cursor) => cursor,
                    Err(e) => {
                        pb.suspend(|| {
                            error!("Failed to open reader: {}", e);
                            error!("Worker #{} has been suspended", i);
                        });
                        return;
                    }
                };

                loop {
                    let hash = {
                        let mut lock = pending_hashes.lock().unwrap();
                        if let Some(entry) = lock.pop() {
                            entry
                        } else {
                            break;
                        }
                    };

                    let result: anyhow::Result<()> = (|| {
                        let mut data = Vec::new();
                        if !reader.read_content_into(&hash, &mut data)? {
                            anyhow::bail!("Content not found");
                        }

                        // Strip wrapper header if present
                        let raw_data = strip_content_wrapper(&data);

                        // Determine output format based on metadata
                        if convert {
                            if let Some(metadata) = content_metadata.get(&hash) {
                                match metadata {
                                    ContentMetadata::Image { width, height, format, level_count, debug_name } => {
                                        let base_w = *width as usize;
                                        let base_h = *height as usize;
                                        let levels_to_extract = if mipmaps { *level_count } else { 1 };

                                        // Calculate total size needed for all mipmap levels
                                        let mut total_size = 0;
                                        for level in 0..levels_to_extract {
                                            let w = (base_w >> level).max(1);
                                            let h = (base_h >> level).max(1);
                                            total_size += size_of_format(*format, w, h);
                                        }

                                        // Validate data size before attempting to decode
                                        if raw_data.is_empty() {
                                            pb.suspend(|| {
                                                warn!("Empty data for image {}, saving to failed/", hash);
                                            });
                                            let content_type = if organize { "failed" } else { "" };
                                            let file_name = generate_filename(&hash, "bin", debug_name.as_deref(), use_debug_names);
                                            let path = get_output_path(output_dir, organize, content_type, &file_name);
                                            std::fs::create_dir_all(path.parent().unwrap())?;
                                            let mut file = File::create(&path)?;
                                            file.write_all(&data)?;
                                            return Ok(());
                                        }

                                        if raw_data.len() < total_size {
                                            pb.suspend(|| {
                                                warn!("Insufficient data for mipmaps {}: need {}, have {}, extracting single level", hash, total_size, raw_data.len());
                                            });
                                            // Fall back to single level
                                        }

                                        let mut offset = 0;
                                        let mut extracted_any = false;
                                        for level in 0..levels_to_extract {
                                            let w = (base_w >> level).max(1);
                                            let h = (base_h >> level).max(1);
                                            let level_size = size_of_format(*format, w, h);

                                            // Bounds check before slicing
                                            if offset + level_size > raw_data.len() {
                                                if level == 0 {
                                                    // Can't even extract base level
                                                    pb.suspend(|| {
                                                        warn!("Insufficient data for base level {}: need {}, have {}, saving to failed/", hash, level_size, raw_data.len());
                                                    });
                                                    let content_type = if organize { "failed" } else { "" };
                                                    let file_name = generate_filename(&hash, "bin", debug_name.as_deref(), use_debug_names);
                                                    let path = get_output_path(output_dir, organize, content_type, &file_name);
                                                    std::fs::create_dir_all(path.parent().unwrap())?;
                                                    let mut file = File::create(&path)?;
                                                    file.write_all(&data)?;
                                                    return Ok(());
                                                }
                                                break;
                                            }

                                            let level_data = &raw_data[offset..offset + level_size];
                                            let mut rgba = vec![0u8; w * h * 4];

                                            // Use catch_unwind to handle panics from block compression library
                                            let decode_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                                decode_image(*format, w, h, level_data, &mut rgba)
                                            }));

                                            match decode_result {
                                                Ok(Ok(())) => {
                                                    // Decode succeeded
                                                }
                                                Ok(Err(e)) => {
                                                    if level == 0 {
                                                        // Only warn for base level
                                                        pb.suspend(|| {
                                                            warn!("Failed to decode image {} level {}: {}, saving to failed/", hash, level, e);
                                                        });
                                                        let content_type = if organize { "failed" } else { "" };
                                                        let file_name = generate_filename(&hash, "bin", debug_name.as_deref(), use_debug_names);
                                                        let path = get_output_path(output_dir, organize, content_type, &file_name);
                                                        std::fs::create_dir_all(path.parent().unwrap())?;
                                                        let mut file = File::create(&path)?;
                                                        file.write_all(&data)?;
                                                        return Ok(());
                                                    }
                                                    offset += level_size;
                                                    continue;
                                                }
                                                Err(_) => {
                                                    // Panic occurred during decode
                                                    if level == 0 {
                                                        pb.suspend(|| {
                                                            warn!("Panic during decode of image {} level {}, saving to failed/", hash, level);
                                                        });
                                                        let content_type = if organize { "failed" } else { "" };
                                                        let file_name = generate_filename(&hash, "bin", debug_name.as_deref(), use_debug_names);
                                                        let path = get_output_path(output_dir, organize, content_type, &file_name);
                                                        std::fs::create_dir_all(path.parent().unwrap())?;
                                                        let mut file = File::create(&path)?;
                                                        file.write_all(&data)?;
                                                        return Ok(());
                                                    }
                                                    offset += level_size;
                                                    continue;
                                                }
                                            }

                                            // Encode as PNG
                                            let mut png_data = Vec::new();
                                            {
                                                let mut encoder = png::Encoder::new(&mut png_data, w as u32, h as u32);
                                                encoder.set_color(png::ColorType::Rgba);
                                                encoder.set_depth(png::BitDepth::Eight);
                                                let mut writer = encoder.write_header()?;
                                                writer.write_image_data(&rgba)?;
                                            }

                                            // Generate filename with level suffix if multiple mipmaps
                                            let extension = if levels_to_extract > 1 {
                                                format!("_mip{}.png", level)
                                            } else {
                                                ".png".to_string()
                                            };

                                            let file_name = generate_filename(&hash, &extension, debug_name.as_deref(), use_debug_names);
                                            // Determine content type based on dimensions (icons are typically small square textures)
                                            let content_type = if organize {
                                                if base_w <= 512 && base_h <= 512 && base_w == base_h {
                                                    "icons"
                                                } else {
                                                    "textures"
                                                }
                                            } else {
                                                ""
                                            };
                                            let path = get_output_path(output_dir, organize, content_type, &file_name);
                                            std::fs::create_dir_all(path.parent().unwrap())?;
                                            let mut file = File::create(&path)?;
                                            file.write_all(&png_data)?;

                                            extracted_any = true;
                                            offset += level_size;
                                        }

                                        if !extracted_any {
                                            // No mipmaps were successfully extracted, save to failed folder
                                            pb.suspend(|| {
                                                warn!("No mipmaps extracted for {}, saving to failed/", hash);
                                            });
                                            let content_type = if organize { "failed" } else { "" };
                                            let file_name = generate_filename(&hash, "bin", debug_name.as_deref(), use_debug_names);
                                            let path = get_output_path(output_dir, organize, content_type, &file_name);
                                            std::fs::create_dir_all(path.parent().unwrap())?;
                                            let mut file = File::create(&path)?;
                                            file.write_all(&data)?;
                                        }
                                    }
                                    ContentMetadata::Audio { channels, sample_rate, frame_count, debug_name } => {
                                        // Convert to WAV
                                        let mut wav_data = Vec::new();
                                        let cursor = Cursor::new(raw_data);
                                        let wav_cursor = Cursor::new(&mut wav_data);

                                        if let Err(e) = deserialize_audio(cursor, wav_cursor, *channels, *sample_rate, *frame_count) {
                                            // Fall back to raw binary if conversion fails
                                            pb.suspend(|| {
                                                warn!("Failed to convert audio {}: {}, saving to failed/", hash, e);
                                            });
                                            let content_type = if organize { "failed" } else { "" };
                                            let file_name = generate_filename(&hash, "bin", debug_name.as_deref(), use_debug_names);
                                            let path = get_output_path(output_dir, organize, content_type, &file_name);
                                            std::fs::create_dir_all(path.parent().unwrap())?;
                                            let mut file = File::create(&path)?;
                                            file.write_all(&data)?;
                                        } else {
                                            let content_type = if organize { "audio" } else { "" };
                                            let file_name = generate_filename(&hash, "wav", debug_name.as_deref(), use_debug_names);
                                            let path = get_output_path(output_dir, organize, content_type, &file_name);
                                            std::fs::create_dir_all(path.parent().unwrap())?;
                                            let mut file = File::create(&path)?;
                                            file.write_all(&wav_data)?;
                                        }
                                    }
                                }
                            } else {
                                // No metadata, save as raw binary
                                let content_type = if organize { "unknown" } else { "" };
                                let file_name = generate_filename(&hash, "bin", None, use_debug_names);
                                let path = get_output_path(output_dir, organize, content_type, &file_name);
                                std::fs::create_dir_all(path.parent().unwrap())?;
                                let mut file = File::create(&path)?;
                                file.write_all(&data)?;
                            }
                        } else {
                            // No conversion, save as raw binary
                            let content_type = if organize { "unknown" } else { "" };
                            let file_name = generate_filename(&hash, "bin", None, use_debug_names);
                            let path = get_output_path(output_dir, organize, content_type, &file_name);
                            std::fs::create_dir_all(path.parent().unwrap())?;
                            let mut file = File::create(&path)?;
                            file.write_all(&data)?;
                        }

                        Ok(())
                    })();

                    match result {
                        Ok(()) => {},
                        Err(e) => {
                            failed_extracts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                            pb.suspend(|| {
                                error!("Error extracting content `{}`: {}", hash, e);
                            });
                        }
                    }

                    pb.inc(1);
                }
            });

            handles.push(handle);
        }

        for handle in handles {
            if let Err(_) = handle.join() {
                // Thread panicked - errors are already logged by the panic handler
                // The failed_extracts counter will be updated by error handling in the thread
            }
        }
    });

    pb.finish_and_clear();

    let failed_extracts = failed_extracts.load(std::sync::atomic::Ordering::Relaxed);
    let end = std::time::Instant::now();

    info!("Extracted a total of {}/{} content blobs in {:?}", total - failed_extracts, total, end - start);

    Ok(())
}

fn import_content(
    game_dir: &Path,
    file_name: Option<&str>,
    input_dir: &Path,
    _thread_count: u8,
) -> Result<(), Error> {
    if !game_dir.exists() {
        fatal!("Game directory does not exist: {}", game_dir.display());
    }

    if !input_dir.exists() {
        fatal!("Input directory does not exist: {}", input_dir.display());
    }

    let kfc_path = get_file(game_dir, file_name, "kfc")?;
    let kfc_path_bak = get_file_opt(game_dir, file_name, "kfc.bak")?;

    if kfc_path_bak.exists() && !validate_backup(&kfc_path, &kfc_path_bak)? {
        warn!("Backup file is not valid, deleting it...");

        if !kfc_path_bak.is_file() {
            fatal!("Backup path is not a file, please remove it manually: {}", kfc_path_bak.display())
        }

        if let Err(e) = std::fs::remove_file(&kfc_path_bak) {
            fatal!("Failed to delete backup file: {}", e);
        }
    }

    if !kfc_path_bak.exists() {
        info!("Creating backup of {}...", kfc_path.display());

        match std::fs::copy(&kfc_path, &kfc_path_bak) {
            Ok(_) => {},
            Err(e) => fatal!("Failed to create backup: {}", e)
        }
    }

    let type_registry = load_type_registry(Some(game_dir), file_name, true)?;

    let mut ref_kfc_file = match KFCFile::from_path(&kfc_path_bak, false) {
        Ok(file) => file,
        Err(e) => fatal!("Failed to read {}: {}", kfc_path_bak.display(), e)
    };

    // Collect .bin files from input directory
    let files: Vec<PathBuf> = WalkDir::new(input_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path().extension().map(|x| x == "bin").unwrap_or(false))
        .map(|e| e.path().to_path_buf())
        .collect();

    if files.is_empty() {
        fatal!("No .bin files found in input directory");
    }

    info!("Importing {} content blobs from {}", files.len(), input_dir.display());

    let file_name_str = get_file_name(game_dir, file_name)?;

    let mut writer = match KFCWriter::new_incremental(
        game_dir,
        &file_name_str,
        &mut ref_kfc_file,
        &type_registry
    ) {
        Ok(writer) => writer,
        Err(e) => fatal!("Failed to open writer: {}", e)
    };

    let pb = ProgressBar::new(files.len() as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template(&format!("{} Importing... [{{bar:40}}] {{pos:>7}}/{{len:7}} {{msg}}", "info:".blue().bold()))
        .unwrap()
        .progress_chars("##-"));

    let total = files.len() as u32;
    let failed_imports = AtomicU32::new(0);
    let start = std::time::Instant::now();

    for file_path in &files {
        let result: anyhow::Result<()> = (|| {
            // Parse content hash from filename (without .bin extension)
            let stem = file_path.file_stem()
                .and_then(|s| s.to_str())
                .ok_or_else(|| anyhow::anyhow!("Invalid filename"))?;

            // Read the content data
            let data = std::fs::read(file_path)?;

            // Generate content hash from data
            let content_hash = ContentHash::from_data(&data);

            // Optionally verify it matches the filename (if filename is a valid hash)
            if let Some(expected_hash) = ContentHash::parse(stem) {
                if expected_hash != content_hash {
                    warn!("Content hash mismatch for {}: expected {}, got {}",
                        file_path.display(), expected_hash, content_hash);
                }
            }

            // Write the content
            writer.write_content(&content_hash, &data)?;

            Ok(())
        })();

        match result {
            Ok(()) => {},
            Err(e) => {
                failed_imports.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                pb.suspend(|| {
                    error!("Error importing content `{}`: {}", file_path.display(), e);
                });
            }
        }

        pb.inc(1);
    }

    pb.finish_and_clear();

    match writer.finalize() {
        Ok(()) => {},
        Err(e) => {
            error!("Failed to finalize writer: {}", e);
            return revert_repack(game_dir, file_name, true);
        }
    }

    let failed_imports = failed_imports.load(std::sync::atomic::Ordering::Relaxed);
    let end = std::time::Instant::now();

    info!("Imported a total of {}/{} content blobs in {:?}", total - failed_imports, total, end - start);

    Ok(())
}

#[derive(Debug, Error)]
pub enum TypeParseError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}
