use std::collections::HashMap;
use std::fmt::{Display, Formatter};

use arboard::Clipboard;
use clap::{Parser, Subcommand, ValueEnum};
use colored::{ColoredString, Colorize};
use human_panic::setup_panic;
use rand::prelude::*;
use serde::ser::{SerializeStruct, Serializer};
use serde::Serialize;
use term_table::row::Row;
use term_table::table_cell::{Alignment, TableCell};
use term_table::{Table, TableStyle};
use zxcvbn::zxcvbn;

#[derive(Parser, Debug)]
#[command(name = "motus")]
#[command(version = "0.1.0")]
#[command(about = "A command-line tool to generate secure passwords")]
#[command(
long_about = "Motus is a command-line tool for generating secure, random, and memorable passwords as well as PIN codes."
)]
struct Cli {

    #[command(subcommand)]
    command:Commands,

    /// 禁用自动复制生成的密码到剪贴板
    #[arg(long)]
    no_clipboard:bool,

    /// 以指定格式输出生成的密码
    #[arg(short,long, default_value = "text", value_enum)]
    output:OutputFormat,

    /// 根据生成的密码显示安全分析
    #[arg(long)]
    analyze:bool,

    /// 用于确定密码生成的种子值(用于测试目的)
    #[arg(long)]
    seed:Option<u64>

}

#[derive(Debug,Subcommand)]
enum Commands {

    #[command(name = "pin")]
    #[command(about = "Generate a random numeric PIN code")]
    #[command(
    long_about = "Generate a random numeric Personal Identification Number (PIN) code with a configurable length."
    )]
    Pin {
        /// 指定生成的PIN码的位数
        #[arg(short, long, default_value = "7")]
        numbers: u32
    },
}

fn main() {
    // 启用人类可读的紧急信息
    setup_panic!();

    // 解析命令行参数
    let opts:Cli = Cli::parse();

    //初始化随机源
    //如果提供了一个种子，使用它来播种随机源
    //否则，使用主线程的随机源
    let mut rng:Box<dyn RngCore> = match opts.seed {
        Some(seed) => Box::new(StdRng::seed_from_u64(seed)),
        None => Box::new(thread_rng()),
    };

    let password = match opts.command {
        Commands::Pin {numbers} => motus::pin_password(&mut rng, numbers),
    };

    // 将密码复制到剪贴板
    if !opts.no_clipboard {
        let mut clipboard =
            Clipboard::new().expect("unable to interact with your system's clipboard");
        clipboard
            .set_text(&password)
            .expect("unable to set clipboard contents");
    }

    match opts.output {
        OutputFormat::Text => {
            if opts.analyze {
                let analysis = SecurityAnalysis::new(&password);
                analysis.display_report(TableStyle::extended(), 80)
            } else {
                println!("{}", password);
            }
        }
        OutputFormat::Json => {
            let output = PasswordOutput{
                kind: match opts.command {
                    Commands::Pin {..} => PasswordKind::Pin,
                },
                password: &password,
                analysis: if opts.analyze {
                    Some(SecurityAnalysis::new(&password))
                } else {
                    None
                },
            };
            println!("{}", serde_json::to_string(&output).unwrap());
        }
    }

}

#[derive(ValueEnum, Clone,Debug)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Serialize)]
struct PasswordOutput<'a> {
    kind:PasswordKind,
    password: &'a str,

    #[serde(skip_serializing_if = "Option::is_none")]
    analysis:Option<SecurityAnalysis<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum PasswordKind {
    Pin,
}


struct SecurityAnalysis<'a> {
    password: &'a str,
    entropy: zxcvbn::Entropy,
}


impl Display for PasswordKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PasswordKind::Pin => write!(f,"pin"),
        }
    }
}

impl Serialize for SecurityAnalysis<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        let mut crack_times = HashMap::new();
        crack_times.insert(
            "100/h",
            self.entropy
                .crack_times()
                .online_throttling_100_per_hour()
                .to_string(),
        );

        crack_times.insert(
            "10/s",
            self.entropy
                .crack_times()
                .online_no_throttling_10_per_second()
                .to_string(),
        );

        crack_times.insert(
            "10^4/s",
            self.entropy
                .crack_times()
                .offline_slow_hashing_1e4_per_second()
                .to_string(),
        );

        crack_times.insert(
            "10^10/s",
            self.entropy
                .crack_times()
                .offline_fast_hashing_1e10_per_second()
                .to_string(),
        );

        let mut struct_serializer = serializer.serialize_struct("SecurityAnalysis",3)?;
        struct_serializer.serialize_field(
            "strength",
            &PasswordStrength::from(self.entropy.score()).to_string(),
        )?;

        struct_serializer.serialize_field(
            "guesses",
            format!("10^{:.0}", &self.entropy.guesses_log10()).as_str(),
        )?;
        struct_serializer.serialize_field("crack_times", &crack_times)?;
        struct_serializer.end()
    }
}

impl <'a> SecurityAnalysis<'a> {
    fn new(password: &'a str) -> Self {
        let entropy = zxcvbn(password, &[]).expect("unable to analyze password's safety");
        Self { password, entropy }
    }

    fn display_report(&self, table_style: TableStyle, max_width: usize) {
        self.display_password_table(table_style,max_width);
        self.display_analysis_table(table_style,max_width);
        self.display_crack_times_table(table_style,max_width);
    }

    fn display_password_table(&self, table_style: TableStyle, max_width: usize) {
        let mut table = Table::new();
        table.max_column_width = max_width;
        table.style = table_style;

        table.add_row(Row::new(vec![TableCell::new_with_alignment(
            "Generated Password".bold(),
            1,
            Alignment::Left,
        )]));

        table.add_row(Row::new(vec![TableCell::new(self.password)]));

        println!("{}", table.render());
    }

    fn display_analysis_table(&self, table_style: TableStyle, max_width: usize) {
        let mut table = Table::new();
        table.max_column_width = max_width;
        table.style = table_style;

        table.add_row(Row::new(vec![TableCell::new_with_alignment(
            "Security Analysis",
            2,
            Alignment::Left,
        )]));

        table.add_row(Row::new(vec![
            TableCell::new("Strength".bold()),
            TableCell::new_with_alignment(
                PasswordStrength::from(self.entropy.score()).to_colored_string(),
                1,
                Alignment::Left,
            ),
        ]));

        table.add_row(Row::new(vec![
            TableCell::new("Guesses".bold()),
            TableCell::new_with_alignment(
                format!("10^{:.0}", self.entropy.guesses_log10()),
                1,
                Alignment::Left,
            ),
        ]));

        println!("{}", table.render());
    }

    fn display_crack_times_table(&self, table_style: TableStyle, max_width: usize) {
        let mut table = Table::new();
        table.max_column_width = max_width;
        table.style = table_style;

        table.add_row(Row::new(vec![TableCell::new_with_alignment(
            "Security Analysis",
            2,
            Alignment::Left,
        )]));

        table.add_row(Row::new(vec![
            TableCell::new("100 attempts/hour".bold()),
            TableCell::new_with_alignment(
                format!("{}",self.entropy.crack_times().online_throttling_100_per_hour()),
                1,
                Alignment::Left,
            ),
        ]));

        table.add_row(Row::new(vec![
            TableCell::new("10 attempts/second".bold()),
            TableCell::new_with_alignment(
                format!(
                    "{}",
                    self.entropy
                        .crack_times()
                        .online_no_throttling_10_per_second()
                ),
                1,
                Alignment::Left,
            ),
        ]));

        table.add_row(Row::new(vec![
            TableCell::new("10^4 attempts/second".bold()),
            TableCell::new_with_alignment(
                format!(
                    "{}",
                    self.entropy
                        .crack_times()
                        .offline_slow_hashing_1e4_per_second()
                ),
                1,
                Alignment::Left,
            ),
        ]));

        table.add_row(Row::new(vec![
            TableCell::new("10^10 attempts/second".bold()),
            TableCell::new_with_alignment(
                format!(
                    "{}",
                    self.entropy
                        .crack_times()
                        .offline_fast_hashing_1e10_per_second()
                ),
                1,
                Alignment::Left,
            ),
        ]));

        println!("{}", table.render());
    }

}

enum PasswordStrength {
    VeryWeak,
    Weak,
    Reasonable,
    Strong,
    VeryStrong,
}

impl From<u8> for PasswordStrength {
    fn from(score: u8) -> Self {
        match score {
            0 => PasswordStrength::VeryWeak,
            1 => PasswordStrength::Weak,
            2 => PasswordStrength::Reasonable,
            3 => PasswordStrength::Strong,
            4 => PasswordStrength::VeryStrong,
            _ => panic!("invalid score"),
        }
    }
}

impl PasswordStrength {
    fn to_colored_string(&self) -> ColoredString {
        match self {
            PasswordStrength::VeryWeak => self.to_string().red(),
            PasswordStrength::Weak => self.to_string().bright_red(),
            PasswordStrength::Reasonable => self.to_string().yellow(),
            PasswordStrength::Strong => self.to_string().bright_green(),
            PasswordStrength::VeryStrong  => self.to_string().green(),
        }
    }
}

impl Display for PasswordStrength{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let strength = match self {
            PasswordStrength::VeryWeak => "very week",
            PasswordStrength::Weak => "week",
            PasswordStrength::Reasonable => "reasonable",
            PasswordStrength::Strong => "strong",
            PasswordStrength::VeryStrong => "very strong",
        };
        write!(f, "{}", strength)
    }
}

fn validate_word_count(s: &str) -> Result<u32, String> {
    match s.parse::<u32>() {
        Ok(n) if(3..16).contains(&n) => Ok(n),
        Ok(_) => Err("The number of words must be between 4 and 15".to_string()),
        Err(_) => Err("The number of words must be an integer".to_string())
    }
}

fn validate_character_count(s: &str) -> Result<u32, String> {
    match s.parse::<u32>() {
        Ok(n) if(8..101).contains(&n) => Ok(n),
        Ok(_) => Err("The number of words must be between 8 and 100".to_string()),
        Err(_) => Err("The number of words must be an integer".to_string()),
    }
}

fn validate_pin_length(s: &str) -> Result<u32, String> {
    match s.parse::<u32>() {
        Ok(n) if (3..13).contains(&n) => Ok(n),
        Ok(_) => Err("The number of words must be between 3 and 12".to_string()),
        Err(_) => Err("The number of words must be an integer".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_word_count() {
        assert!(validate_word_count("2").is_err());
        assert!(validate_word_count("3").is_ok());
        assert!(validate_word_count("15").is_ok());
        assert!(validate_word_count("16").is_err());
    }

    #[test]
    fn test_validate_character_count() {
        assert!(validate_character_count("7").is_err());
        assert!(validate_character_count("8").is_ok());
        assert!(validate_character_count("100").is_ok());
        assert!(validate_character_count("101").is_err());
    }

    #[test]
    fn test_validate_pin_length() {
        assert!(validate_pin_length("2").is_err());
        assert!(validate_pin_length("3").is_ok());
        assert!(validate_pin_length("12").is_ok());
        assert!(validate_pin_length("13").is_err());
    }
}