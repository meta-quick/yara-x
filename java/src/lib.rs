use std::ptr::{addr_of, slice_from_raw_parts_mut};
use anyhow::Result;
use jni::objects::{JClass, JObject, JString,JObjectArray};
use jni::sys::{jlong,jboolean, jobjectArray, jstring};
use jni::JNIEnv;
use yara_x as yrx;

fn throw_err<T>(mut env: JNIEnv, mut f: impl FnMut(&mut JNIEnv) -> Result<T>) -> Result<T> {
    match f(&mut env) {
        Ok(val) => Ok(val),
        Err(err) => {
            env.throw(err.to_string())?;
            Err(err)
        }
    }
}

struct Compiler {
    inner: yrx::Compiler<'static>,
    relaxed_re_syntax: bool,
    error_on_slow_pattern: bool,
}

impl Compiler {
    fn new_inner(
        relaxed_re_syntax: bool,
        error_on_slow_pattern: bool,
    ) -> yrx::Compiler<'static> {
        let mut compiler = yrx::Compiler::new();
        if relaxed_re_syntax {
            compiler.relaxed_re_syntax(true);
        }
        if error_on_slow_pattern {
            compiler.error_on_slow_pattern(true);
        }
        compiler
    }

    fn add_source(&mut self, src: &str) -> Result<()> {
        self.inner
            .add_source(src)
            .map_err(|err| CompileError::new_err(err.to_string()))?;
        Ok(())
    }
}

#[no_mangle]
pub extern "system" fn Java_com_datasafe_yara_Engine_nativeNewYaraCompiler(
    _env: JNIEnv,
    _class: JClass,
    relaxed_re_syntax: jboolean,
    error_on_slow_pattern: jboolean,
) -> jlong {
    let compiler = Compiler::new_inner(
        relaxed_re_syntax != 0,
        error_on_slow_pattern != 0,
    );
    Box::into_raw(Box::new(compiler)) as jlong
}
