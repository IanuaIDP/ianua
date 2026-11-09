//! How each runtime starts a version's code: the file the code is written
//! to, the small entry script that calls it, and the command that runs
//! that script.
//!
//! The entry reads the input as JSON on standard input, calls the code,
//! and writes what it gave back as JSON to standard output. Anything the
//! code prints itself goes to standard error, so it can never be taken
//! for the answer. Python code defines `main(input)`; JavaScript code
//! exports one function, `module.exports = (input) => ...`, which may be
//! async.

use ianua_domain::domains::workflows::sandbox::runtime::{Language, Runtime};

/// Where a sandbox finds its version's files: the code, its entry and its
/// bundle's packages.
pub(super) const MOUNTED_AT: &str = "/sandbox";

/// The folder of the entry script, beside the code.
pub(super) const ENTRY_FOLDER: &str = ".ianua";

/// How `runtime` starts a version's code.
pub(super) struct Entry {
    /// The file the code is written to, under the sandbox.
    pub(super) code_file: &'static str,
    /// The entry script's file, under [`ENTRY_FOLDER`].
    pub(super) entry_file: &'static str,
    /// What the entry script holds.
    pub(super) script: &'static str,
    /// The interpreter that runs it.
    pub(super) interpreter: &'static str,
    /// Settings the interpreter is started with.
    pub(super) environment: &'static [(&'static str, &'static str)],
}

/// The entry `runtime` starts its code through: one for every Python, one
/// for every Node.
pub(super) fn entry_of(runtime: Runtime) -> Entry {
    match runtime.language() {
        Language::Python => Entry {
            code_file: "main.py",
            entry_file: "run.py",
            script: PYTHON_ENTRY,
            interpreter: "python3",
            environment: &[
                ("PYTHONDONTWRITEBYTECODE", "1"),
                ("PYTHONNOUSERSITE", "1"),
                ("PYTHONSAFEPATH", "1"),
            ],
        },
        Language::JavaScript => Entry {
            code_file: "main.js",
            entry_file: "run.js",
            script: NODE_ENTRY,
            interpreter: "node",
            environment: &[("NODE_PATH", "/sandbox/node_modules")],
        },
    }
}

const PYTHON_ENTRY: &str = r#"import json
import os
import sys

answer = os.fdopen(os.dup(1), "w")
os.dup2(2, 1)
sys.path.insert(0, "/sandbox/python")
sys.path.insert(0, "/sandbox")
given = json.load(sys.stdin)
import main
result = main.main(given)
answer.write(json.dumps(result))
answer.flush()
"#;

const NODE_ENTRY: &str = r#"'use strict';
const fs = require('fs');
const toErr = (...parts) => { process.stderr.write(parts.map(String).join(' ') + '\n'); };
console.log = toErr;
console.info = toErr;
console.debug = toErr;
process.stdout.write = (chunk, ...rest) => process.stderr.write(chunk, ...rest);
const given = JSON.parse(fs.readFileSync(0, 'utf8'));
const code = require('/sandbox/main.js');
Promise.resolve()
  .then(() => code(given))
  .then(
    (result) => { fs.writeSync(1, JSON.stringify(result === undefined ? null : result)); },
    (error) => { process.stderr.write(String((error && error.stack) || error) + '\n'); process.exit(1); },
  );
"#;
