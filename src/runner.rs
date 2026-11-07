use std::cell::RefCell;
use std::process::Command;

#[derive(Clone, Debug, Default)]
pub struct Output {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

pub trait CommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<Output, String>;
}

/// Runs real (unprivileged, read-only) commands. Never used for applying changes.
pub struct RealRunner;

impl CommandRunner for RealRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<Output, String> {
        let mut cmd = Command::new(program);
        cmd.args(args);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        }
        let out = cmd.output().map_err(|e| format!("cannot run {program}: {e}"))?;
        Ok(Output {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
}

/// Test double: returns canned output for the first rule whose key is a prefix of
/// "program arg1 arg2 ..." and records every call.
#[derive(Default)]
pub struct MockRunner {
    rules: Vec<(String, Result<Output, String>)>,
    pub calls: RefCell<Vec<String>>,
}

impl MockRunner {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn on(mut self, prefix: &str, stdout: &str, code: i32) -> Self {
        self.rules.push((prefix.to_string(), Ok(Output { code, stdout: stdout.into(), stderr: String::new() })));
        self
    }
    pub fn fail(mut self, prefix: &str, msg: &str) -> Self {
        self.rules.push((prefix.to_string(), Err(msg.to_string())));
        self
    }
}

impl CommandRunner for MockRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<Output, String> {
        let line = std::iter::once(program).chain(args.iter().copied()).collect::<Vec<_>>().join(" ");
        self.calls.borrow_mut().push(line.clone());
        for (k, v) in &self.rules {
            if line.starts_with(k.as_str()) {
                return v.clone();
            }
        }
        Err(format!("mock: no rule for '{line}'"))
    }
}
