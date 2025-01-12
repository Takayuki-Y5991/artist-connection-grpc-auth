use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    tonic_build::configure()
        .protoc_arg("--experimental_allow_proto3_optional")
        .out_dir("src/generated")
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/auth.proto"], &["proto"])?;
    Ok(())
}
