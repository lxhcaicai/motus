use std::sync::Arc;

use clap::ValueEnum;
use itertools::Itertools;
use lazy_static::lazy_static;
use rand::distributions::{Uniform, WeightedIndex};
use rand::prelude::*;

pub fn pin_password<R:Rng>(rng: &mut R, numbers: u32) -> String {
    (0..numbers)
        .map(|_| NUMBER_CHARS[rng.gen_range(0..NUMBER_CHARS.len())])
        .collect()
}


const NUMBER_CHARS: &[char] = &['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];

// LETTER_CHARS是可用于密码的数字列表
const LETTER_CHARS: &[char] = &[
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
    'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
];

// SYMBOL_CHARS 可用于密码的符号列表
const SYMBOL_CHARS: &[char] = &['!', '@', '#', '$', '%', '^', '&', '*', '(', ')'];

/// 生成具有指定长度和可选包含数字和符号的随机密码。
///
/// 此函数创建具有所需字符数的随机密码
/// 根据提供的布尔标志，生成的密码可以包括字母、数字和符号。
///
/// # Arguments
///
/// * `rng: &mut R` - 一个对随机数生成器的可变引用
/// * `characters: u32` - 密码所需的字符数
/// * `numbers: bool` - 指示密码中是否应包含数字的标志
/// * `symbols: bool` - 指示密码中是否应包含符号的标志
///
/// # Returns
///
/// * `String` - 生成的随机密码
///
/// # Examples
///
/// ```
/// use rand::thread_rng;
/// use motus::random_password;
///
/// let mut rng = thread_rng();
/// let password = random_password(&mut rng, 12, true, true);
/// assert_eq!(password.len(), 12);
/// ```
pub fn random_password<R: Rng>(
    rng: &mut R,
    characters: u32,
    numbers: bool,
    symbols: bool,
) -> String {
    let mut available_sets = vec![LETTER_CHARS];

    if numbers {
        available_sets.push(NUMBER_CHARS);
    }

    if symbols {
        available_sets.push(SYMBOL_CHARS);
    }

    let weights: Vec<u32> = match (numbers,symbols) {

        // 我们采用以下分布:70%字母，20%数字，10%符号。
        (true, true) => vec![7,2,1],

        // 确保我们应用以下分布:80%字母，20%数字
        (true, false) => vec![8, 2],
        (false, true) => vec![8, 2],

        //确保应用以下分布:100%字母
        (false, false) => vec![10],
    };

    let dist_set = WeightedIndex::new(&weights).expect("weights should be valid");
    let mut password = String::with_capacity(characters as usize);

    for _ in 0..characters {
        let selected_set = available_sets
            .get(dist_set.sample(rng))
            .expect("index should be valid");
        let dist_char = Uniform::from(0..selected_set.len());
        let index = dist_char.sample(rng);
        password.push(selected_set[index]);
    }

    password

}