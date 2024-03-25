use anyhow::Context;
use dbgeng::client::DebugClient;
use dbgeng::export_cmd;

fn breakonprocess(client: &DebugClient, args: String) -> Result<(), anyhow::Error> {
    let mut args = args.split_whitespace();
    let process_name = args.next().context("missing process name")?;

    Ok(())
}

export_cmd!(breakonprocess);
