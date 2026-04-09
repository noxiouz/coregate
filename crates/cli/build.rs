fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = prost_build::Config::new();
    for message in [
        "coregate.config.ConfigRoot",
        "coregate.config.CollectorConfig",
        "coregate.config.CoreConfig",
        "coregate.config.RateLimitPolicy",
        "coregate.config.RateLimitRule",
        "coregate.config.ConfigOverride",
        "coregate.config.Matcher",
        "coregate.config.SymbolizerConfig",
        "coregate.config.HttpSymbolizerConfig",
    ] {
        config.type_attribute(
            message,
            "#[derive(serde::Serialize, serde::Deserialize)] #[serde(default)]",
        );
    }
    config.type_attribute(
        "coregate.config.Compression",
        "#[derive(serde::Serialize, serde::Deserialize)] #[serde(rename_all = \"snake_case\")]",
    );
    config.type_attribute(
        "coregate.config.SymbolizerMode",
        "#[derive(serde::Serialize, serde::Deserialize)] #[serde(rename_all = \"snake_case\")]",
    );
    config.field_attribute(
        "coregate.config.CoreConfig.compression",
        "#[serde(default, deserialize_with = \"super::deserialize_compression_field\", serialize_with = \"super::serialize_compression_field\")]",
    );
    config.compile_protos(&["proto/config.proto"], &["proto"])?;
    println!("cargo:rerun-if-changed=proto/config.proto");
    Ok(())
}
