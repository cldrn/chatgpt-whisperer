[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/cldrn/chatgpt-whisperer)](https://github.com/cldrn/chatgpt-whisperer/tags)
[![Follow @calderpwn](https://img.shields.io/twitter/follow/calderpwn?style=social)](https://x.com/calderpwn)

# ChatGPTWhisperer for Ghidra

ChatGPTWhisperer is a Ghidra plugin that integrates OpenAI's ChatGPT to assist with reverse engineering tasks. It enables AI-powered function analysis, vulnerability detection, documentation, and batch processing within the Ghidra UI.

Latest Ghidra version tested on:11.3.1
---

## Features

### Function Analysis
- **Describe Function** – Summarize what the current function does.
- **Detect Vulnerabilities** – Perform a vulnerability audit of the selected function.
- **Ask a Custom Question** – Send your own prompt along with the function code.
- **Explain with Xrefs** – Analyze cross-references to understand function context.

### Signature Assistance
- **Suggest Function Signature** – Let ChatGPT suggest return type, name, and parameters.
- **Batch Suggest Signatures** – Apply signature suggestions to multiple functions with filtering.

### Batch Operations
- **Batch Function Analysis** – Identify or analyze vulnerabilities across all (or filtered) functions.
- **Filter Support** – Optionally limit batch actions to function names containing a substring.

### Settings and Customization
- **Set OpenAI Token** – Enter your API key.
- **Set Temperature** – Control randomness of responses.
- **Select Model** – Choose from supported OpenAI models (e.g., gpt-4o, gpt-3.5-turbo).
- **Assistant Persona** – Customize the assistant's behavior/personality.
- **Toggle Append to Comment** – Automatically append responses as comments to functions.
- **Export/Import Settings** – Save or load configuration to a file.

---

## Installation

1. Install the `.zip` file into Ghidra via `File > Install Extensions`.
2. Open the plugin through the `Tools` menu.
---

## Building the extension

1. Use gradle to compile setting your local Ghidra installation path.

`gradle -PGHIDRA_INSTALL_DIR=<Ghidra Path>`

2. The extension will be generated in .zip inside the folder /dist
---

## Requirements
- A valid OpenAI API Token (can be set via environment variable `OPENAI_TOKEN` or UI)
- Internet access to connect to OpenAI’s API

---

## Default Assistant Persona
> You are an expert reverse engineering assistant trained in analyzing low-level code, including firmware, embedded systems, and decompiled binaries. Your role is to explain complex logic, uncover vulnerabilities, and suggest improvements based on secure coding principles. You understand ARM, C, memory layout, and common patterns found in real-world devices.

---

## License
Apache License, Version 2.0. Contributions welcome!

---

## Credits
Inspired by [GhidraChatGPT](https://github.com/likvidera/GhidraChatGPTby) and developed by [PwnLabMX](https://github.com/PwnLabMX) with ❤️ and reverse engineering in mind.

---

## Legal Notice

This plugin is provided **"as is"** without any warranty or guarantee of any kind, express or implied. The use of this plugin is at the sole risk and responsibility of the user. By using this plugin, you acknowledge and agree that:

- You are solely responsible for how you use the plugin and for the results obtained from its usage.
- The authors and contributors are not liable for any damages, data loss, system compromise, or other issues that may arise directly or indirectly from the use of this software.
- You must comply with all applicable laws, regulations, and terms of service for any platform or software you analyze or interact with using this tool.
- This project is not affiliated with or endorsed by the NSA, the Ghidra project, or OpenAI.

Always use this plugin responsibly and ethically.
