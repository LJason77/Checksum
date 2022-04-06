#![deny(clippy::pedantic)]
#![allow(clippy::non_ascii_literal)]

use std::{
    env::{current_dir, var},
    error::Error,
    fs::{create_dir_all, read_dir, File},
    io::copy,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread::{sleep, spawn},
    time::Duration,
};

use clap::Parser;
use rusqlite::Connection;
use sha2::{Digest, Sha256};

/// 视频的后缀
const EXTENSIONS: [&str; 10] = [
    "avi", "flv", "m2ts", "mkv", "mov", "mp4", "rmvb", "ts", "webm", "wmv",
];

static NEW_FILE: AtomicUsize = AtomicUsize::new(0);
static TASK: AtomicUsize = AtomicUsize::new(0);

/// 检查目录中所有文件的 sha256sum 值
#[derive(Parser)]
#[clap(about, version, author)]
struct Checksum {
    /// 更新数据库
    #[clap(short = 'u', long = "update")]
    update: bool,
    /// 同时执行多个任务
    #[clap(short = 'j', long = "jobs")]
    jobs: Option<usize>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Checksum = Checksum::parse();
    let update = args.update;
    let jobs = args.jobs.unwrap_or_else(num_cpus::get);

    let db_dir = format!("{}/.db", var("HOME")?);
    create_dir_all(&db_dir)?;
    let conn = Connection::open(format!("{}/checksuns.db", db_dir))?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS checksuns (
            id INTEGER PRIMARY KEY,
            file TEXT NOT NULL UNIQUE,
            sha256sum TEXT NOT NULL
        )",
        [],
    )?;

    let (tx, rx) = mpsc::channel();
    let mut files = Vec::new();
    // 当前路径
    let current_dir = current_dir()?;
    walk_dir(&current_dir, &mut files);

    spawn(move || {
        for path in files {
            let mut file = File::open(&path).unwrap();
            let len = file.metadata().unwrap().len() / 1000;
            'l: loop {
                if TASK.load(Ordering::Relaxed) < jobs {
                    break 'l;
                }
                sleep(Duration::from_secs(len));
            }
            let tx = tx.clone();
            spawn(move || {
                TASK.fetch_add(1, Ordering::SeqCst);
                let sha256sum = get_sha256sum(&mut file).unwrap();
                TASK.fetch_sub(1, Ordering::SeqCst);
                tx.send((path, sha256sum)).unwrap();
            });
        }
    });

    for (path, sha256sum) in rx {
        let file = path.to_str().unwrap();
        let mut stmt = conn
            .prepare("SELECT id, file, sha256sum FROM checksuns WHERE file = ?")
            .unwrap();
        let mut rows = stmt.query(&[&file]).unwrap();
        if let Some(row) = rows.next().unwrap() {
            let row_id: i64 = row.get(0).unwrap();
            let row_file: String = row.get(1).unwrap();
            let row_sha256sum: String = row.get(2).unwrap();
            if row_sha256sum != sha256sum {
                println!("文件：{} 已更改", row_file);
                if update {
                    conn.execute(
                        "UPDATE checksuns SET sha256sum = ? WHERE id = ?",
                        [&sha256sum, &row_id.to_string()],
                    )
                    .unwrap();
                }
            }
        } else {
            NEW_FILE.fetch_add(1, Ordering::SeqCst);
            println!("新文件： {}\n{}", file, sha256sum);
            if update {
                conn.execute(
                    "INSERT INTO checksuns (file, sha256sum) VALUES (?, ?)",
                    &[&file, &sha256sum.as_str()],
                )
                .unwrap();
            }
        }
    }
    println!("共有 {} 个新文件", NEW_FILE.load(Ordering::SeqCst));
    Ok(())
}

/// 遍历目录
fn walk_dir(dir: &Path, files: &mut Vec<PathBuf>) {
    for result in read_dir(dir).unwrap() {
        let dir_entry = result.unwrap();
        let path_buf = dir_entry.path();
        if path_buf.is_dir() {
            walk_dir(&path_buf, files);
        } else if let Some(ext) = path_buf.extension() {
            if EXTENSIONS.contains(&ext.to_str().unwrap()) {
                files.push(path_buf);
            }
        }
    }
}

/// 获得文件的 sha256sum
fn get_sha256sum(file: &mut File) -> Result<String, Box<dyn Error>> {
    let mut hasher = Sha256::new();
    copy(file, &mut hasher)?;
    let hash = hasher.finalize();
    Ok(hex::encode(hash))
}
