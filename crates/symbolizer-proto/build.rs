fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = prost_build::Config::new();
    for message in [
        "coregate.symbolizer.SymbolizationRequest",
        "coregate.symbolizer.ProcessInfo",
        "coregate.symbolizer.Module",
        "coregate.symbolizer.SymbolizationFrame",
        "coregate.symbolizer.NormalizedFrame",
        "coregate.symbolizer.SymbolizationResponse",
        "coregate.symbolizer.SymbolizedFrame",
    ] {
        config.type_attribute(
            message,
            "#[derive(serde::Serialize, serde::Deserialize)] #[serde(default)]",
        );
    }
    config.compile_protos(&["proto/symbolizer.proto"], &["proto"])?;
    println!("cargo:rerun-if-changed=proto/symbolizer.proto");
    Ok(())
}
