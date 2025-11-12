pub struct Executable<AddressType> {
    bytes: Box<[u8]>,
    sections: Vec<(AddressType, usize)>
}

