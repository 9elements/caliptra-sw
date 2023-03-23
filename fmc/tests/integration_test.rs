// Licensed under the Apache-2.0 license

#[test]
fn it_works() {
    let rom_elf = caliptra_builder::build_firmware_elf("caliptra-fmc", "caliptra-fmc").unwrap();
}
