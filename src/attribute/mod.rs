#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct Attribute {
    bytes: Vec<u8>,
}

impl Attribute {
    const ATTRIBUTE_SIZE: usize = 128;
    const HASH_MAP: u32 = 1;
    const PROGRAM_TYPE: u32 = 15;
    const DEVICE_ATTACHMENT: u32 = 6;
    const LOG_LEVEL: u32 = 1;

    pub(crate) fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    pub(crate) fn compose_map(key_size: u32, value_size: u32, entry_limit: u32) -> Self {
        let mut attribute = Self::compose_empty();
        attribute.write_word(0, Self::HASH_MAP);
        attribute.write_word(4, key_size);
        attribute.write_word(8, value_size);
        attribute.write_word(12, entry_limit);
        attribute
    }

    pub(crate) fn compose_update(
        map_descriptor: u32,
        key_address: u64,
        value_address: u64,
    ) -> Self {
        let mut attribute = Self::compose_empty();
        attribute.write_word(0, map_descriptor);
        attribute.write_address(8, key_address);
        attribute.write_address(16, value_address);
        attribute
    }

    pub(crate) fn compose_deletion(map_descriptor: u32, key_address: u64) -> Self {
        let mut attribute = Self::compose_empty();
        attribute.write_word(0, map_descriptor);
        attribute.write_address(8, key_address);
        attribute
    }

    pub(crate) fn compose_program(
        instruction_count: u32,
        instruction_address: u64,
        license_address: u64,
        log_size: u32,
        log_address: u64,
    ) -> Self {
        let mut attribute = Self::compose_empty();
        attribute.write_word(0, Self::PROGRAM_TYPE);
        attribute.write_word(4, instruction_count);
        attribute.write_address(8, instruction_address);
        attribute.write_address(16, license_address);
        attribute.write_word(24, Self::LOG_LEVEL);
        attribute.write_word(28, log_size);
        attribute.write_address(32, log_address);
        attribute.write_word(68, Self::DEVICE_ATTACHMENT);
        attribute
    }

    pub(crate) fn compose_pin(path_address: u64, descriptor: u32) -> Self {
        let mut attribute = Self::compose_empty();
        attribute.write_address(0, path_address);
        attribute.write_word(8, descriptor);
        attribute
    }

    pub(crate) fn compose_lookup(path_address: u64) -> Self {
        let mut attribute = Self::compose_empty();
        attribute.write_address(0, path_address);
        attribute
    }

    pub(crate) fn compose_attachment(
        target_descriptor: u32,
        program_descriptor: u32,
        flags: u32,
    ) -> Self {
        let mut attribute = Self::compose_empty();
        attribute.write_word(0, target_descriptor);
        attribute.write_word(4, program_descriptor);
        attribute.write_word(8, Self::DEVICE_ATTACHMENT);
        attribute.write_word(12, flags);
        attribute
    }

    fn compose_empty() -> Self {
        let bytes = vec![0; Self::ATTRIBUTE_SIZE];
        Self { bytes }
    }

    fn write_word(&mut self, offset: usize, word: u32) {
        self.bytes[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
    }

    fn write_address(&mut self, offset: usize, address: u64) {
        self.bytes[offset..offset + 8].copy_from_slice(&address.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod fixture {
        use super::*;

        pub(crate) fn word_factory(attribute: &Attribute, offset: usize) -> u32 {
            let mut word = [0; 4];
            word.copy_from_slice(&attribute.bytes[offset..offset + 4]);
            u32::from_le_bytes(word)
        }

        pub(crate) fn address_factory(attribute: &Attribute, offset: usize) -> u64 {
            let mut address = [0; 8];
            address.copy_from_slice(&attribute.bytes[offset..offset + 8]);
            u64::from_le_bytes(address)
        }
    }

    #[test]
    fn a_map_attribute_holds_a_hash_map_and_its_sizes() {
        let attribute = Attribute::compose_map(12, 4, 256);

        assert_eq!(fixture::word_factory(&attribute, 0), 1);
        assert_eq!(fixture::word_factory(&attribute, 4), 12);
        assert_eq!(fixture::word_factory(&attribute, 8), 4);
        assert_eq!(fixture::word_factory(&attribute, 12), 256);
        assert_eq!(attribute.bytes.len(), 128);
    }

    #[test]
    fn the_map_attributes_hold_the_descriptor_the_key_and_the_value() {
        let update = Attribute::compose_update(5, 0x1000, 0x2000);
        let deletion = Attribute::compose_deletion(5, 0x1000);

        assert_eq!(fixture::word_factory(&update, 0), 5);
        assert_eq!(fixture::address_factory(&update, 8), 0x1000);
        assert_eq!(fixture::address_factory(&update, 16), 0x2000);
        assert_eq!(fixture::word_factory(&update, 24), 0);
        assert_eq!(fixture::word_factory(&deletion, 0), 5);
        assert_eq!(fixture::address_factory(&deletion, 8), 0x1000);
    }

    #[test]
    fn a_program_attribute_holds_the_code_the_license_and_the_attachment() {
        let attribute = Attribute::compose_program(39, 0x1000, 0x2000, 65536, 0x3000);

        assert_eq!(fixture::word_factory(&attribute, 0), 15);
        assert_eq!(fixture::word_factory(&attribute, 4), 39);
        assert_eq!(fixture::address_factory(&attribute, 8), 0x1000);
        assert_eq!(fixture::address_factory(&attribute, 16), 0x2000);
        assert_eq!(fixture::word_factory(&attribute, 24), 1);
        assert_eq!(fixture::word_factory(&attribute, 28), 65536);
        assert_eq!(fixture::address_factory(&attribute, 32), 0x3000);
        assert_eq!(fixture::word_factory(&attribute, 68), 6);
    }

    #[test]
    fn the_object_attributes_hold_the_path_and_the_descriptor() {
        let pin = Attribute::compose_pin(0x4000, 7);
        let lookup = Attribute::compose_lookup(0x4000);

        assert_eq!(fixture::address_factory(&pin, 0), 0x4000);
        assert_eq!(fixture::word_factory(&pin, 8), 7);
        assert_eq!(fixture::address_factory(&lookup, 0), 0x4000);
    }

    #[test]
    fn an_attachment_attribute_holds_the_descriptors_the_type_and_the_flags() {
        let attachment = Attribute::compose_attachment(3, 4, 2);
        let detachment = Attribute::compose_attachment(3, 4, 0);

        assert_eq!(fixture::word_factory(&attachment, 0), 3);
        assert_eq!(fixture::word_factory(&attachment, 4), 4);
        assert_eq!(fixture::word_factory(&attachment, 8), 6);
        assert_eq!(fixture::word_factory(&attachment, 12), 2);
        assert_eq!(fixture::word_factory(&detachment, 12), 0);
    }
}
