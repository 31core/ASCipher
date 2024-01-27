use crate::{encrypt::Cipher512, hash::Hasher512, KEY_SIZE_512};

#[no_mangle]
pub extern "C" fn new_cipher512(key_raw: *const u8) -> *mut u8 {
    let mut key = [0; KEY_SIZE_512];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = unsafe { *key_raw.add(i) };
    }
    let cipher = Cipher512::new(&key);
    let layout = std::alloc::Layout::new::<Cipher512>();

    unsafe {
        let addr = std::alloc::alloc(layout);
        std::ptr::write(addr as *mut Cipher512, cipher);
        addr
    }
}

#[no_mangle]
pub extern "C" fn cipher512_apply(cipher: *mut u8, data_raw: *mut u8, size: u64) {
    let cipher = unsafe { &mut *(cipher as *mut Cipher512) };

    let mut data = Vec::new();
    for i in 0..size {
        data.push(unsafe { *data_raw.add(i as usize) });
    }
    let data = cipher.apply_any(&data);
    for i in 0..size {
        unsafe {
            *data_raw.add(i as usize) = data[i as usize];
        };
    }
}

#[no_mangle]
pub extern "C" fn new_hasher512() -> *mut u8 {
    let hasher = Hasher512::default();

    let layout = std::alloc::Layout::new::<Hasher512>();
    unsafe {
        let addr = std::alloc::alloc(layout);
        std::ptr::write(addr as *mut Hasher512, hasher);
        addr
    }
}

#[no_mangle]
pub extern "C" fn hash512_update(hasher512: *mut u8, raw_data: *const u8, size: u64) {
    let hasher = unsafe { &mut *(hasher512 as *mut Hasher512) };
    let mut data = vec![0; size as usize];
    for (i, byte) in data.iter_mut().enumerate() {
        *byte = unsafe { *raw_data.add(i) };
    }
    hasher.update(&data);
}

#[no_mangle]
pub extern "C" fn hash512_digest(hasher512: *mut u8, hash: *mut u8) {
    let hasher = unsafe { &mut *(hasher512 as *mut Hasher512) };
    let result = hasher.digest();
    for (i, byte) in result.iter().enumerate() {
        unsafe { *hash.add(i) = *byte };
    }
}
