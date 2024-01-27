use crate::{encrypt::Cipher512, KEY_SIZE_512};

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
