#![deny(clippy::pedantic)]
#![allow(clippy::non_ascii_literal)]

use std::{
    env::{current_dir, var},
    error::Error,
    fs::read_dir,
    path::Path,
    sync::atomic::{AtomicUsize, Ordering},
};

use clap::{crate_version, App, Arg, ArgMatches};
use rusqlite::Connection;
use sha2::{Digest, Sha256};

/// 视频的后缀
const EXTENSIONS: [&str; 10] = [
    "avi", "flv", "m2ts", "mkv", "mov", "mp4", "rmvb", "ts", "webm", "wmv",
];

static NEW_FILE: AtomicUsize = AtomicUsize::new(0);

fn main() -> Result<(), Box<dyn Error>> {
    let matches = app_args();
    let update = matches.is_present("update");

    let db_dir = format!("{}/.db", var("HOME")?);
    std::fs::create_dir_all(&db_dir)?;
    let conn = Connection::open(format!("{}/checksuns.db", db_dir))?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS checksuns (
            id INTEGER PRIMARY KEY,
            file TEXT NOT NULL UNIQUE,
            sha256sum TEXT NOT NULL
        )",
        [],
    )?;

    // 当前路径
    let current_dir = current_dir()?;
    walk_dir(&conn, &current_dir, update);

    println!("共有 {} 个新文件", NEW_FILE.load(Ordering::SeqCst));
    Ok(())
}

/// 遍历目录
fn walk_dir(conn: &Connection, dir: &Path, update: bool) {
    let files = read_dir(dir).unwrap();
    for dir_entry in files {
        let file = dir_entry.unwrap();
        let path = file.path();
        if path.is_dir() {
            walk_dir(conn, &path, update);
        } else if let Some(ext) = path.extension() {
            if EXTENSIONS.contains(&ext.to_str().unwrap()) {
                let file = path.to_str().unwrap();
                let mut stmt = conn
                    .prepare("SELECT id, file, sha256sum FROM checksuns WHERE file = ?")
                    .unwrap();
                let mut rows = stmt.query(&[&file]).unwrap();

                let sha256sum = get_sha256sum(&path).unwrap();
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
                    println!("新文件： {}\n{}\n", file, sha256sum);
                    if update {
                        conn.execute(
                            "INSERT INTO checksuns (file, sha256sum) VALUES (?, ?)",
                            &[&file, &sha256sum.as_str()],
                        )
                        .unwrap();
                    }
                }
            }
        }
    }
}

/// 获得文件的 md5sum
fn get_sha256sum(path: &Path) -> Result<String, Box<dyn Error>> {
    let mut hasher = Sha256::new();
    let mut file = std::fs::File::open(path)?;
    std::io::copy(&mut file, &mut hasher)?;
    let hash = hasher.finalize();
    Ok(hex::encode(hash))
}

fn app_args<'a>() -> ArgMatches<'a> {
    App::new("checksum")
        .author("LJason")
        .version(crate_version!())
        .arg(
            Arg::with_name("update")
                .help("更新数据库")
                .long("update")
                .short("u")
                .takes_value(false),
        )
        .get_matches()
}
