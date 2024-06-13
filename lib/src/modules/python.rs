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

    let mut num_lines = 0;
    let mut num_words = 0;

    // Create cursor for iterating over the lines.
    let cursor = io::Cursor::new(data);

    // Count the lines and words in the file.
    for line in cursor.lines() {
        match line {
            Ok(line) => {
                num_words += line.split_whitespace().count();
                num_lines += 1;
            }
            Err(_) => return python_proto,
        }
    }

    // Set the value for fields `num_lines` and `num_words` in the protobuf.
    python_proto.set_num_lines(num_lines as i64);
    python_proto.set_num_words(num_words as i64);

    // Return the Text proto after filling the relevant fields.
    python_proto
}

/// Function that eval input script against the scanned data`.
#[module_export]
fn eval(ctx: &mut ScanContext,script :RuntimeString) -> Option<bool> {
    // Obtain a reference to the `Text` protobuf that was returned by the
    // module's main function.
    let text = ctx.module_output::<Python>()?;

    let num_lines = text.num_lines? as f64;
    let num_words = text.num_words? as f64;
    let script = script.to_str(ctx).unwrap();

    println!("hello: {}", script);
    Some(true)
}


