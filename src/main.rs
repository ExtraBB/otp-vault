use clap::{AppSettings, Parser, Subcommand};
use ring::{hmac};
use otp_vault;

#[derive(Parser)]
#[clap(about, version, author)]
#[clap(global_setting(AppSettings::PropagateVersion))]
#[clap(global_setting(AppSettings::UseLongFormatForHelpSubcommand))]
#[clap(setting(AppSettings::SubcommandRequiredElseHelp))]
struct CLI {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new OTP vault
    Create { 
        /// Location to store the vault
        path: String 
    },

    /// Add a new OTP profile
    Add { 
        /// Location of the vault
        path: String,

        // Hash of the OTP profile
        hash: String
    },

    /// Get an OTP code
    Get { 
        /// Location of the vault
        path: String,

        /// identifier of the OTP profile
        id: String
    },

    /// Prints the profiles in the vault
    List { 
        /// Location of the vault
        path: String 
    },

    /// Prints some debug info
    Debug { },
}

fn main() {
    let cli = CLI::parse();

    match &cli.command {
        Commands::Create { path } => {
            println!("Not implemented yet");
        }
        Commands::Add { path, hash } => {
            println!("Not implemented yet");
        }
        Commands::Get { path, id } => {
            println!("Not implemented yet");
        }
        Commands::List { path } => {
            println!("Not implemented yet");
        }
        Commands::Debug { } => {
            let token_source = otp_vault::TokenSource {
                key: String::from("test"),
                interval_seconds: 30,
                algorithm: hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
                digits: 6
            };

            let token = token_source.generate_totp_token();
            println!("{}", token);
        }
    }
}