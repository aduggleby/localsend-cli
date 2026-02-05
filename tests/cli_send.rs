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

fn spawn_receiver_with_pin(output_dir: &Path, port: u16, pin: &str) -> ReceiverGuard {
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
        .arg("--pin")
        .arg(pin)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    wait_for_port(port, Duration::from_secs(5));
    ReceiverGuard { child }
}

fn spawn_webshare(text: &str, port: u16) -> ReceiverGuard {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("localsend-cli"));
    let child = cmd
        .arg("webshare")
        .arg("--text")
        .arg(text)
        .arg("--bind")
        .arg("127.0.0.1")
        .arg("--port")
        .arg(port.to_string())
        .arg("--protocol")
        .arg("http")
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

fn http_get(host_port: &str, path: &str) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(host_port).unwrap();
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, host_port
    );
    use std::io::Write;
    stream.write_all(request.as_bytes()).unwrap();
    let mut buf = Vec::new();
    use std::io::Read;
    stream.read_to_end(&mut buf).unwrap();
    let response = String::from_utf8_lossy(&buf);
    let status = response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    (status, buf)
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

#[test]
#[serial]
fn send_requires_pin_errors_without_pin() {
    let temp_dir = tempfile::tempdir().unwrap();
    let port = pick_port();
    let _receiver = spawn_receiver_with_pin(temp_dir.path(), port, "1234");

    Command::new(assert_cmd::cargo::cargo_bin!("localsend-cli"))
        .arg("send")
        .arg("--to")
        .arg("127.0.0.1")
        .arg("--direct")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--text")
        .arg("hello")
        .arg("--timeout")
        .arg("3")
        .assert()
        .failure();
}

#[test]
#[serial]
fn send_no_payload_errors() {
    Command::new(assert_cmd::cargo::cargo_bin!("localsend-cli"))
        .arg("send")
        .arg("--to")
        .arg("127.0.0.1")
        .arg("--direct")
        .arg("127.0.0.1:1")
        .arg("--timeout")
        .arg("1")
        .assert()
        .failure();
}

#[test]
#[serial]
fn webshare_serves_content() {
    let port = pick_port();
    let _webshare = spawn_webshare("webshare-test", port);

    let host_port = format!("127.0.0.1:{port}");
    let (status, body) = http_get(&host_port, "/");
    assert_eq!(status, 200);
    let body_str = String::from_utf8_lossy(&body);
    let link_start = body_str.find("/files/").expect("expected file link");
    let link = &body_str[link_start..];
    let link_end = link.find('"').unwrap_or(link.len());
    let path = &link[..link_end];

    let (file_status, file_body) = http_get(&host_port, path);
    assert_eq!(file_status, 200);
    assert!(String::from_utf8_lossy(&file_body).contains("webshare-test"));
}

#[test]
#[serial]
fn send_qr_fallback_prints_url() {
    let port = pick_port();
    let mut child = Command::new(assert_cmd::cargo::cargo_bin!("localsend-cli"))
        .arg("webshare")
        .arg("--text")
        .arg("hello")
        .arg("--bind")
        .arg("127.0.0.1")
        .arg("--port")
        .arg(port.to_string())
        .arg("--protocol")
        .arg("http")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    thread::sleep(Duration::from_secs(3));
    let _ = child.kill();
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("QR send ready."), "expected QR banner");
    assert!(stdout.contains("http"), "expected URL in output");
}
