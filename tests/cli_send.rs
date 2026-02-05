use assert_cmd::prelude::*;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use serial_test::serial;

struct ReceiverGuard {
    child: Child,
}

impl Drop for ReceiverGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

static NEXT_PORT: AtomicU16 = AtomicU16::new(40000);

fn pick_port() -> u16 {
    loop {
        let port = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
        if port >= 60000 {
            NEXT_PORT.store(40000, Ordering::SeqCst);
            continue;
        }
        if TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok() {
            return port;
        }
    }
}

fn wait_for_port(port: u16, timeout: Duration) {
    let start = Instant::now();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    while start.elapsed() < timeout {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("receiver did not start in time on port {port}");
}

fn spawn_receiver(output_dir: &Path, port: u16) -> ReceiverGuard {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("localsend-cli"));
    let child = cmd
        .arg("receive")
        .arg("--output")
        .arg(output_dir)
        .arg("--bind")
        .arg("127.0.0.1")
        .arg("--port")
        .arg(port.to_string())
        .arg("--protocol")
        .arg("https")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    wait_for_port(port, Duration::from_secs(5));
    ReceiverGuard { child }
}

fn run_send(args: &[&str]) {
    Command::new(assert_cmd::cargo::cargo_bin!("localsend-cli"))
        .args(args)
        .assert()
        .success();
}

fn read_all_files(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_file() {
            entries.push((path.clone(), fs::read(&path).unwrap()));
        }
    }
    entries
}

#[test]
#[serial]
fn send_text_message() {
    let temp_dir = tempfile::tempdir().unwrap();
    let port = pick_port();
    let _receiver = spawn_receiver(temp_dir.path(), port);

    run_send(&[
        "send",
        "--to",
        "127.0.0.1",
        "--direct",
        &format!("127.0.0.1:{port}"),
        "--text",
        "hello",
        "--timeout",
        "3",
    ]);

    let files = read_all_files(temp_dir.path());
    assert!(
        files.iter().any(|(_, content)| content == b"hello"),
        "expected a file containing 'hello'"
    );
}

#[test]
#[serial]
fn send_single_file() {
    let temp_dir = tempfile::tempdir().unwrap();
    let port = pick_port();
    let _receiver = spawn_receiver(temp_dir.path(), port);

    let send_dir = tempfile::tempdir().unwrap();
    let file_path = send_dir.path().join("sample.bin");
    fs::write(&file_path, b"localsend-cli").unwrap();

    run_send(&[
        "send",
        "--to",
        "127.0.0.1",
        "--direct",
        &format!("127.0.0.1:{port}"),
        "--file",
        file_path.to_str().unwrap(),
        "--timeout",
        "3",
    ]);

    let files = read_all_files(temp_dir.path());
    assert!(
        files.iter().any(|(path, content)| {
            path.file_name().unwrap() == "sample.bin" && content == b"localsend-cli"
        }),
        "expected sample.bin to be received"
    );
}

#[test]
#[serial]
fn send_glob_files() {
    let temp_dir = tempfile::tempdir().unwrap();
    let port = pick_port();
    let _receiver = spawn_receiver(temp_dir.path(), port);

    let send_dir = tempfile::tempdir().unwrap();
    fs::write(send_dir.path().join("a.txt"), b"a").unwrap();
    fs::write(send_dir.path().join("b.txt"), b"b").unwrap();

    let pattern = format!("{}/*.txt", send_dir.path().display());

    run_send(&[
        "send",
        "--to",
        "127.0.0.1",
        "--direct",
        &format!("127.0.0.1:{port}"),
        "--glob",
        &pattern,
        "--timeout",
        "3",
    ]);

    let files = read_all_files(temp_dir.path());
    let names: Vec<String> = files
        .iter()
        .map(|(path, _)| path.file_name().unwrap().to_string_lossy().to_string())
        .collect();

    assert!(names.contains(&"a.txt".to_string()));
    assert!(names.contains(&"b.txt".to_string()));
}

#[test]
#[serial]
fn send_directory_as_zip() {
    let temp_dir = tempfile::tempdir().unwrap();
    let port = pick_port();
    let _receiver = spawn_receiver(temp_dir.path(), port);

    let send_dir = tempfile::tempdir().unwrap();
    let sub = send_dir.path().join("folder");
    fs::create_dir_all(&sub).unwrap();
    fs::write(sub.join("one.txt"), b"one").unwrap();
    fs::write(sub.join("two.txt"), b"two").unwrap();

    run_send(&[
        "send",
        "--to",
        "127.0.0.1",
        "--direct",
        &format!("127.0.0.1:{port}"),
        "--dir",
        sub.to_str().unwrap(),
        "--timeout",
        "3",
    ]);

    let files = read_all_files(temp_dir.path());
    assert_eq!(files.len(), 1, "expected one zip file");
    let (_, content) = &files[0];
    assert!(content.starts_with(b"PK"), "expected a zip file");
}
