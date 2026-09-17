//! Stamp the git commit into the binary (`sbc --version`, startup log) so a
//! production box can always say which build is live. Prefers the
//! `SBC_GIT_SHA` env (set by scripts/deploy.sh, whose remote source tree
//! is an rsync copy without .git), then `git rev-parse`, else "unknown".

fn main() {
    let sha = std::env::var("SBC_GIT_SHA")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::process::Command::new("git")
                .args(["rev-parse", "--short=12", "HEAD"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=SBC_GIT_SHA={}", sha);
    println!("cargo:rerun-if-env-changed=SBC_GIT_SHA");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs/heads");
}
