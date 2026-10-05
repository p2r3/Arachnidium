## Arachnidium

Data-optimizing HTTP(S) proxy, powered by [mitmproxy](https://www.mitmproxy.org/).

## Setup

0. Find a home server - this can be any internet-connected computer, like an old laptop. Currently, pre-built releases exist for x64 Windows and Linux. If you need ARM or Mac support, clone the repository and run it from source.
1. On your home server, download the portable archive for your system in [Releases](https://github.com/p2r3/Arachnidium/releases/tag/latest).
2. Extract the archive and run `Arachnidium.exe` (or `Arachnidium` on Linux).
3. Install the WireGuard client on your device: [Android](https://play.google.com/store/apps/details?id=com.wireguard.android&pli=1) | [iOS](https://apps.apple.com/us/app/wireguard/id1441195209)
4. Add the VPN preset using the QR code displayed in Arachnidium. Alternatively, use the automatically generated `wireguard.cfg` file.
5. This is where things get a little hairy - if you want to actually use this outside of your home WiFi, you'll have to configure your network to listen for incoming VPN connections. To do this, you will have to forward **UDP** port **51820** from your home server to your router. The exact process for this is vastly different for every network and router, and it would be impossible to give a universal guide in this document, so please research this yourself. Searching for "port forward udp \<router model\>" should be enough to get you on the right track. Alternatively, call your internet service provider and ask if they can help.
6. Connect to the VPN and visit `mitm.it` on your phone's browser. Follow the instructions there to set up the certificate authority. ***Make sure to read all of the instructions.***

If you run into issues, please make sure you've followed these steps carefully. Do your own troubleshooting first to make sure the issue isn't on your end (e.g. misconfigured network). Please do not message me personally asking for help - I sadly don't have the time (or patience) to be able to assist everyone, sorry.

## Running with Docker

Arachnidium can also run headless in Docker, which works on any x64 or ARM64 Linux machine (e.g. a Raspberry Pi) without installing Python or Bun:

1. Download [`compose.yaml`](compose.yaml) (or clone this repository) and run `docker compose up -d`.
2. Follow the setup above from step 3. For step 4, run `docker compose logs arachnidium` to see the WireGuard QR code.

Your WireGuard keys and mitmproxy's certificate authority are kept in the `data` volume, so they survive updates. To change settings, place `defaults.json` next to `compose.yaml` and uncomment its line in `compose.yaml` (keep `ENABLE_GUI` set to `false`).

To update, run `docker compose pull && docker compose up -d`. To build the image from source instead, run `docker compose up -d --build`.

## Configuration

There are two ways to configure Arachnidium: via the graphical interface, or by editing `defaults.json`. Changes made in the GUI are not saved between restarts - for that, use the JSON file. If you want to run Arachnidium without the GUI, set `ENABLE_GUI` to `false` in `defaults.json`, and the WireGuard QR code will be printed to the console instead.

## Running from source

To run this project from source code without building it (for development purposes, or to run on unsupported platforms):

1. Install Python and [uv](https://docs.astral.sh/uv/).
2. Install [Bun](https://bun.sh/).
3. Clone this repository with submodules (using `--recursive`).
4. Run `uv run main.py`
5. In another terminal, change directory to `bun-api` and run `bun i`, then `bun run index.ts`

## Contributing

Contributions are welcome, though please note that I am personally unlikely to continue working on this project in the long term. This was something that I've wanted to experiment with for a while, but unlike some of my other projects, I have little intention of actually growing this into its own thing. I might still merge pull requests from time to time, but I probably won't close issues on my own (unless it's something critical).

Before submitting an issue, make sure you've read and followed the usage instructions carefully and have done your own troubleshooting. I would prefer that you do not use LLMs in submitted code, but if you do, please be transparent about it. State where an LLM was used, and explain (in your own words) what it did.

## Acknowledgements

- https://www.mitmproxy.org/
- https://github.com/rdbende/Azure-ttk-theme

The name "Arachnidium" is a homage to nature's earliest web developers. The arachnidium is, generally, [the part of a spider's body responsible for producing webs](https://www.merriam-webster.com/dictionary/arachnidium). It also sounds really cool.
