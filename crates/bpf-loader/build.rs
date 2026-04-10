use std::env;
use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let src = PathBuf::from("src/bpf/stacktrace.bpf.c");

    libbpf_cargo::SkeletonBuilder::new()
        .source(src)
        .clang_args(["-Isrc/bpf"])
        .build_and_generate(out.join("stacktrace.skel.rs"))
        .expect("generate BPF skeleton");

    println!("cargo:rerun-if-changed=src/bpf/stacktrace.bpf.c");
    println!("cargo:rerun-if-changed=src/bpf/minimal_bpf.h");
}
