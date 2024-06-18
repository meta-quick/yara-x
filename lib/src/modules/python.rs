use std::io;
use std::io::BufRead;
// Example "text" module described in the Module's Developer Guide.
//
use crate::modules::prelude::*;
use crate::modules::protos::python::*;

use rhai::{Engine, Scope, Dynamic, INT};

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
    let script = script.to_str(ctx).unwrap();
    let data  = text.scanned();
    let mut engine = Engine::new();
    let mut scope = Scope::new();

    // Create an array and push the scanned data into it.
    let rhai_array = data.iter().map(|x| Dynamic::from(*x as INT)).collect::<Vec<_>>();
    scope.push("scanned", rhai_array);
    // Convert data to lines of strings
    let data_lines = lines_udata(&data);
    scope.push("scanned_lines", data_lines);

    engine.register_fn("lines", lines);


    let result = engine.run_with_scope(&mut scope, script);
    match result {
       Ok(_) => {
          let scope_result =  scope.get_value::<bool>("result");
           match scope_result {
               Some(br) => {
                   return Some(br);
               }
               None => {
                   return Some(false);
               }
           }
       }
       Err(err) => {
           println!("{}", err);
           return Some(false);
       }
    }
}

fn lines(data:  Vec<Dynamic>) -> Vec<Dynamic> {
    let xdata = data.iter().map(|x| x.as_int().unwrap() as u8).collect::<Vec<u8>>();
    return lines_udata(&xdata);
}

fn lines_udata(data:  &[u8]) -> Vec<Dynamic> {
    let cursor = io::Cursor::new(data);

    let mut lines = Vec::new();

    for line in cursor.lines() {
        match line {
            Ok(line) => {
                lines.push(line);
            }
            Err(_) => { },
        }
    }
    let dynamic_array = lines.into_iter()
        .map(Dynamic::from)
        .collect();

    return dynamic_array;
}

