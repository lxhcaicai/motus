use rand::Rng;

pub fn pin_password<R:Rng>(rng: &mut R, numbers: u32) -> String {
    (0..numbers)
        .map(|_| NUMBER_CHARS[rng.gen_range(0..NUMBER_CHARS.len())])
        .collect()
}

// LETTER_CHARS是可用于密码的数字列表
const NUMBER_CHARS: &[char] = &['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];