// Example "text" module described in the Module's Developer Guide.
//
use crate::modules::prelude::*;
use crate::modules::protos::python::*;

use std::io;
use std::io::BufRead;

use lingua::{Language, LanguageDetectorBuilder};

/// Module's main function.
///
/// The main function is called for every file that is scanned by YARA. The
/// `#[module_main]` attribute indicates that this is the module's main
/// function. The name of the function is irrelevant, but using `main` is
/// advised for consistency.
///
/// This function must return an instance of the protobuf message indicated
/// in the `root_message` option in `python.proto`.
#[module_main]
fn main(data: &[u8]) -> Python {
    // Create an empty instance of the Text protobuf.
    let mut python_proto = Python::new();
    // Set the value for fields `num_lines` and `num_words` in the protobuf.
    python_proto.set_scanned(data.into());

    // Return the Text proto after filling the relevant fields.
    python_proto
}

/// Function that eval input script against the scanned data`.
#[module_export]
fn eval(ctx: &mut ScanContext,script :RuntimeString) -> Option<bool> {
    // Obtain a reference to the `Text` protobuf that was returned by the
    // module's main function.
    let text = ctx.module_output::<Python>()?;

    // Create cursor for iterating over the lines.
    let data = text.scanned();
    let cursor = io::Cursor::new(data);

    // Count the lines and words in the file.
    let mut line_count = 0;
    for line in cursor.lines() {
        match line {
            Ok(line) => {
                // num_words += line.split_whitespace().count();
                line_count += 1;
            }
            Err(_) => return Some(false),
        }
    }
    println!("line_count: {}", line_count);


    let script = script.to_str(ctx).unwrap();
    Some(true)
}


