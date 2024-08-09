use core::marker::PhantomPinned;
use core::mem;
use std::any::Any;
use std::fs;
use std::ops::Deref;
use std::path::PathBuf;
use std::pin::Pin;

use anyhow::{anyhow, Context, Error, Result};
use crossterm::style::Stylize;
use jni::JNIEnv;
use jni::objects::{JClass, JString, JByteArray, JObject};
use jni::sys::{jboolean, jlong, jstring};
use protobuf::MessageDyn;
use protobuf_json_mapping::print_to_string;
use serde_json::{json, Map, Value};

use yara_x as yrx;
use yara_x::Variable;
use yara_x::SourceCode;

pub mod walk;

pub struct YaraXCompiler<'a> {
    inner: yrx::Compiler<'a>,
    relaxed_re_syntax: bool,
    error_on_slow_pattern: bool,
}

impl<'a> YaraXCompiler<'a>{
    pub fn new(
        relaxed_re_syntax: bool,
        error_on_slow_pattern: bool,
    ) -> Self {
        Self {
            inner: Self::new_inner(relaxed_re_syntax, error_on_slow_pattern),
            relaxed_re_syntax,
            error_on_slow_pattern,
        }
    }

    pub fn new_inner(
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

    pub fn add_source(&mut self, src: &str) -> Result<()> {
        let result = self.inner.add_source(src);
        if let Err(err) = result {
            return Err(err.into());
        }

        Ok(())
    }

    pub fn add_paths(&mut self, paths: Vec<PathBuf>, path_as_namespace: bool) -> Result<()> {
        for path in &paths {
            let mut w = walk::Walker::path(path.as_path());

            w.filter("**/*.yar");
            w.filter("**/*.yara");

            if let Err(err) = w.walk(
                |file_path| {
                    let src = fs::read(file_path).with_context(|| {
                        format!("can not read `{}`", file_path.display())
                    })?;

                    let src = SourceCode::from(src.as_slice())
                        .with_origin(file_path.as_os_str().to_str().unwrap());

                    if path_as_namespace {
                        self.inner.new_namespace(file_path.to_string_lossy().as_ref());
                    }

                    let result =  self.inner.add_source(src);
                    Ok(())
                },
                // Any error occurred during walk is aborts the walk.
                Err,
            ) {
                return Err(err);
            }
        }
        Ok(())
    }

    pub fn ignore_module(&mut self, module_name: &str) -> Result<()> {
        let _ = self.inner.ignore_module(module_name);
        Ok(())
    }
    pub fn new_namespace(&mut self, namespace_name: &str) -> Result<()> {
        let _ = self.inner.new_namespace(namespace_name);
        Ok(())
    }

    pub fn define_global<T: TryInto<Variable>>(
        &mut self,
        ident: &str,
        value: T,
    ) -> Result<(),Error>
    where
        yara_x::Error: From<<T as TryInto<Variable>>::Error> {
        let result = self.inner.define_global(ident, value);
        match result {
            Ok(_) => { Ok(())}
            Err(_) => {
                Err(anyhow!("Failed to define global variable"))
            }
        }
    }

    pub fn build(&mut self) -> Result<yrx::Rules> {
        // let result = self.inner.take().build();
        let compiler = mem::replace(
            &mut self.inner,
            Self::new_inner(
                self.relaxed_re_syntax,
                self.error_on_slow_pattern,
            )
        );
        let result = compiler.build();
        Ok(result)
    }
}

pub struct PinnedRules {
    rules: yrx::Rules,
    _pinned: PhantomPinned,
}
pub struct Rules {
    inner: Pin<Box<PinnedRules>>,
}

impl Rules {
    fn new(rules: yrx::Rules) -> Self {
        Rules {
            inner: Box::pin(PinnedRules { rules, _pinned: PhantomPinned }),
        }
    }

    pub fn scan(
        &self,
        data: &[u8],
    ) -> Result<ScanResults> {
        let binding = self.inner.as_ref();
        let mut scanner = yrx::Scanner::new(&binding.rules);
        let result = scanner.scan(data);
        match result {
            Ok(results) => {
                Ok(scan_results_java(results))
            }
            Err(err) => {
                Err(anyhow!("Failed to scan data: {}", err))
            }
        }
    }

    pub fn scan_file(
        &self,
        path: &str,
    ) -> Result<ScanResults> {
        let binding = self.inner.as_ref();
        let mut scanner = yrx::Scanner::new(&binding.rules);
        let result = scanner.scan_file(path);
        match result {
            Ok(results) => {
                Ok(scan_results_java(results))
            }
            Err(err) => {
                Err(anyhow!("Failed to scan data: {}", err))
            }
        }
    }
}

trait to_json {
    fn to_json(&self) -> Value;
}

pub struct Pattern {
    identifier: String,
    matches: Vec<Match>,
}

impl to_json for Pattern {
    fn to_json(&self) -> Value {
        let mut result: Map<String, Value> = Map::new();
        result.insert("identifier".to_string(), Value::String(self.identifier.to_string()));

        let mut match_vec: Vec<Value> = vec![];
        for m in &self.matches {
            match_vec.push(m.to_json());
        }
        result.insert("matches".to_string(), Value::Array(match_vec));
        Value::from(result)
    }
}

pub struct Match {
    /// Offset within the scanned data where the match occurred.
    offset: usize,
    /// Length of the match.
    length: usize,
    /// For patterns that have the `xor` modifier, contains the XOR key that
    /// applied to matching data. For any other pattern will be `None`.
    xor_key: Option<u8>,
}

impl to_json for Match {
    fn to_json(&self) -> Value {
        let mut result: Map<String, Value> = Map::new();
        result.insert("offset".to_string(), Value::from(self.offset));
        result.insert("length".to_string(), Value::from(self.length));
        if self.xor_key.is_none() {
            result.insert("xor_key".to_string(), Value::from(false));
        } else {
            result.insert("xor_key".to_string(), Value::from(true));
        }
        Value::from(result)
    }
}

pub struct MetaData {
    ident: String,
    value: String,
}

impl to_json for MetaData {
    fn to_json(&self) -> Value {
        let mut result:Map<String, Value> = Map::new();
        result.insert("ident".to_string(), Value::from(self.ident.to_string()));
        result.insert("value".to_string(), Value::from(self.value.to_string()));
        Value::from(result)
    }
}

pub struct Rule {
    identifier: String,
    namespace: String,
    metadata: Vec<MetaData>,
    patterns: Vec<Pattern>,
}

impl to_json for Rule {
    fn to_json(&self) -> Value {
        let mut result: Map<String, Value> = Map::new();
        result.insert("identifier".to_string(), Value::String(self.identifier.to_string()));
        result.insert("namespace".to_string(), Value::String(self.namespace.to_string()));
        let mut metadata_vec:Vec<Value> = vec![];
        for m in &self.metadata {
            metadata_vec.push(Value::from(m.to_json()));
        }
        result.insert("metadata".to_string(), Value::from(metadata_vec));

        let mut pattern_vec: Vec<Value> = vec![];
        for p in &self.patterns {
            pattern_vec.push(Value::from(p.to_json()));
        }
        result.insert("patterns".to_string(), Value::from(pattern_vec));
        Value::from(result)
    }
}

pub struct ScanResults {
    /// Vector that contains all the rules that matched during the scan.
    matching_rules: Vec<Rule>,
    /// Dictionary where keys are module names and values are other
    /// dictionaries with the information produced by the corresponding module.
    module_outputs: Vec<(String,String)>,
}

impl to_json for ScanResults{
    fn to_json(&self) -> Value {
        let mut result: Map<String, Value> = Map::new();
        let mut rule_vec:Vec<Value> = vec![];
        for r in &self.matching_rules {
            rule_vec.push(Value::from(r.to_json()));
        }
        result.insert("matching_rules".to_string(), Value::from(rule_vec));

        let mut module_map: Map<String, Value> = Map::new();
        for (k, v) in &self.module_outputs {
            module_map.insert(k.to_string(), Value::from(v.to_string()));
        }
        result.insert("module_outputs".to_string(), Value::Object(module_map));
        Value::from(result)
    }
}

pub struct Scanner {
    rule_ref: jlong
}

pub fn metadata_to_java(
    ident: &str,
    metadata: yrx::MetaValue,
) -> MetaData {
    let value = match metadata {
        yrx::MetaValue::Integer(v) => v.to_string(),
        yrx::MetaValue::Float(v) => v.to_string(),
        yrx::MetaValue::Bool(v) => v.to_string(),
        yrx::MetaValue::String(v) => v.to_string(),
        yrx::MetaValue::Bytes(v) => v.to_string(),
    };
    MetaData {
        ident: ident.to_string(),
        value,
    }
}
pub fn rule_to_java( rule: &yrx::Rule) -> Rule {
    Rule {
        identifier: rule.identifier().to_string(),
        namespace: rule.namespace().to_string(),
        metadata: rule.metadata().map(|(ident, value)| metadata_to_java(ident, value)).collect(),
        patterns: rule.patterns().map(|pattern| pattern_to_java(pattern)).collect()
    }
}


pub fn match_to_java(match_: yrx::Match) -> Match {
    Match {
        offset: match_.range().start,
        length: match_.range().len(),
        xor_key: match_.xor_key(),
    }
}
pub fn pattern_to_java(pattern: yrx::Pattern) -> Pattern {
    Pattern {
        identifier: pattern.identifier().to_string(),
        matches: pattern.matches().map(|match_| {
            match_to_java(match_)
        }).collect(),
    }
}
pub fn scan_results_java(scan_results: yrx::ScanResults) -> ScanResults {
    let matching_rules = scan_results
        .matching_rules()
        .map(|rule| rule_to_java(&rule))
        .collect::<Vec<Rule>>();

    let mut module_outputs:  Vec::<(String, String)> = Vec::new();
    for (module, output) in scan_results.module_outputs() {
        let byteout = output.write_to_bytes_dyn();
        if let Ok(bb) = byteout {
            let str = std::str::from_utf8(bb.as_slice());
            if let Ok(s) = str {
                module_outputs.push((module.to_string(),s.to_string()));
                continue;
            }
        }
        let module_output_json = print_to_string(output).unwrap();
        module_outputs.push((module.to_string(),module_output_json));
    }

    ScanResults {
        matching_rules,
        module_outputs,
    }
}

impl<'a>  Scanner{
    pub fn new(rules: jlong) -> Self {
        Scanner {
            rule_ref: rules
        }
    }

    pub fn scan(&mut self, data: &'a [u8]) -> Result<ScanResults> {
        let rules = unsafe { &mut *(self.rule_ref as *mut Rules) };
        rules.scan(data)
    }

    pub fn scan_file(&mut self, path: &str) -> Result<ScanResults> {
        let rules = unsafe { &mut *(self.rule_ref as *mut Rules) };
        rules.scan_file(path)
    }
}



#[cfg(test)]
mod test {
    use crate::Scanner;

    use super::*;

    #[test]
    pub fn test_unicode(){
       let data = b"5YyX5Lqs5aSn5Zyw5byA5Y+R5YWs5Y+4";
       let str = std::str::from_utf8(data).unwrap();
       println!("{}", str);
    }

    #[test]
    pub fn test_scanner() {
        let mut compiler = YaraXCompiler::new(
            true,
            true,
        );

        compiler.new_namespace("foo");
        let re =  compiler.add_source(r###"
import "rhai"
rule CompanyName
{
    meta:
        description = "对企业名称类数据进行自动识别"
        author = "quick"
        name = "企业名称信息"
        level = 3
    strings:
        $_a = /(中国)(有限公司|股份有限公司|集团公司|公司|合伙企业|有限合伙|普通合伙|个人独资企业)/
        $_b = 公司"

    condition:
        rhai.regex(".*公司")
}
"###);
       if let Err(err) = re {
           println!("{}", err);
           return;
       }



        let mut rules = compiler.build();
        if let Ok(mut rules) = rules {
            let pinned = Rules::new(rules);

            let mut scanner = Scanner::new(Box::into_raw(Box::new(pinned)) as jlong);
            // let data = b"\xE4\xBA\xAC1";
            let data = "北京大地开发公司";
            let result = scanner.scan(data.as_bytes());
            let result = result.unwrap().to_json();
            println!("{}", result);
        }
    }
}


fn throw_err<T>(mut env: JNIEnv, mut f: impl FnMut(&mut JNIEnv) -> Result<T>) -> anyhow::Result<T> {
    match f(&mut env) {
        Ok(val) => Ok(val),
        Err(err) => {
            env.throw(err.to_string())?;
            Err(err)
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_datasafe_yara_Engine_nativeNewYaraCompiler<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    relaxed_re_syntax: jboolean,
    error_on_slow_pattern: jboolean,
) -> jlong {
    let compiler = YaraXCompiler::new(
        relaxed_re_syntax != 0,
        error_on_slow_pattern != 0,
    );
    Box::into_raw(Box::new(compiler)) as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_datasafe_yara_Engine_nativeYaraCompilerNewNamespace<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    compiler: jlong,
    ns: JString<'local>,
) -> jlong {
    let result = throw_err(env, |env| {
        let handler = unsafe { &mut *(compiler as *mut YaraXCompiler) };
        let ns: String = env.get_string(&ns)?.into();
        Ok(handler.new_namespace(ns.as_str())?)
    });

    match result {
        Ok(()) => 0,
        Err(err) => {
            -1
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_datasafe_yara_Engine_nativeYaraCompilerAddSource<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    compiler: jlong,
    src: JString<'local>,
) -> jlong {
    let result = throw_err(env, |env| {
        let handler = unsafe { &mut *(compiler as *mut YaraXCompiler) };
        let src: String = env.get_string(&src)?.into();
        Ok(handler.add_source(src.as_str())?)
    });

    match result {
        Ok(()) => 0,
        Err(err) => {
            -1
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_datasafe_yara_Engine_nativeYaraCompilerAddFile<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    compiler: jlong,
    path: JString<'local>,
) -> jlong {
    let result = throw_err(env, |env| {
        let handler = unsafe { &mut *(compiler as *mut YaraXCompiler) };
        let path: String = env.get_string(&path)?.into();
        //split path by ;
        let paths = path.split(";").map(|s| {
            PathBuf::from(s)
        }).collect::<Vec<PathBuf>>();

        handler.add_paths(paths, false)
    });

    match result {
        Ok(()) => 0,
        Err(err) => {
            -1
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_datasafe_yara_Engine_nativeYaraCompilerAddFileWithNamespace<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    compiler: jlong,
    path: JString<'local>,
) -> jlong {
    let result = throw_err(env, |env| {
        let handler = unsafe { &mut *(compiler as *mut YaraXCompiler) };
        let path: String = env.get_string(&path)?.into();
        //split path by ;
        let paths = path.split(";").map(|s| {
            PathBuf::from(s)
        }).collect::<Vec<PathBuf>>();

        handler.add_paths(paths, true)
    });

    match result {
        Ok(()) => 0,
        Err(err) => {
            -1
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_datasafe_yara_Engine_nativeYaraCompilerBuild<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    compiler: jlong,
) -> jlong {
    let result = throw_err(env, |env| {
        let handler = unsafe { &mut *(compiler as *mut YaraXCompiler) };
        let result = handler.build();
        result
    });

    match result {
        Ok(rules) => {
            let pinned = PinnedRules{
                rules,
                _pinned: PhantomPinned,
            };
            let rules = Rules{
                inner: Box::pin(pinned),
            };
            Box::into_raw(Box::new(rules)) as jlong
        }
        Err(err) => {
            -1
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_datasafe_yara_Engine_nativeNewScanner<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    rules: jlong,
) -> jlong {
    let result = throw_err(env, |env| {
        let scanner = Scanner::new(rules);
        Ok(scanner)
    });

    match result {
        Ok(scanner) => {
            Box::into_raw(Box::new(scanner)) as jlong
        }
        Err(err) => {
            -1
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_datasafe_yara_Engine_nativeScannerScan<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    scanner: jlong,
    data: JByteArray<'local>,
) -> jstring {
    let result = throw_err(env, |env| {
        let scanner = unsafe { &mut *(scanner as *mut Scanner) };
        let data = env.convert_byte_array(&data)?;
        let result = scanner.scan(&data);

        if let Ok(result) = result {
            let json = result.to_json();
            let json = json!(json).to_string();
            let jstr = env.new_string(json).unwrap();
            return Ok(jstr.into_raw());
        } else {
            Ok(JObject::null().into_raw())
        }
    });
    match result {
        Ok(result) => {
            result
        }
        Err(err) => {
            JObject::null().into_raw()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_datasafe_yara_Engine_nativeCloseYaraCompiler<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    compiler: jlong,
) -> jlong {
    println!("Closing YARA compiler {}", compiler);
    unsafe {
        let _engine = Box::from_raw(compiler as *mut YaraXCompiler);
    }
    0
}

#[no_mangle]
pub extern "system" fn Java_com_datasafe_yara_Engine_nativeCloseScanner<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    scanner: jlong,
) -> jlong {
    println!("Closing YARA Scanner {}", scanner);
    unsafe {
        let _engine = Box::from_raw(scanner as *mut Scanner);
        let _rule_ref = _engine.rule_ref;
        let _rules = Box::from_raw(_rule_ref as *mut Rules);
    }
    0
}

