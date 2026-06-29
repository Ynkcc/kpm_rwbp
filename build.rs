use std::fs;

fn main() {
    // 获取 git commit 计数
    let count = std::process::Command::new("git")
        .args(["rev-list", "--count", "HEAD"])
        .output()
        .map(|o| String::from_utf8(o.stdout).unwrap().trim().to_string())
        .unwrap_or_else(|_| "0".into());

    // 检测脏构建：工作区有未提交修改则追加 -dirty
    let dirty = std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);

    let version = if dirty {
        format!("version={}-dirty\0", count)
    } else {
        format!("version={}\0", count)
    };

    let out_dir = std::env::var("OUT_DIR").unwrap();
    fs::write(format!("{}/kpm_version.bin", out_dir), version.as_bytes()).unwrap();

    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads/");
    // 工作区文件变更时重新检测脏状态
    println!("cargo:rerun-if-changed=src/");
}
