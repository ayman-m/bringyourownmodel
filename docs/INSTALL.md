# Installing Guardian: start here

Guardian comes as **two editions, one for each platform**. They are different content, built, released and downloaded separately: install only the one that matches your platform.

| Your platform | Download (from the Releases page) | Install guide |
|---|---|---|
| **Cortex XSOAR 6** (6.10 or later) | `Guardian-XSOAR-v<version>.zip` (the release "Guardian for Cortex XSOAR 6") | [**XSOAR 6 install guide**](xsoar/README.md) |
| **Cortex platform** (developed and tested on Cortex XSIAM 8.15) | `Guardian-Cortex-Platform-v<version>.zip` (the release "Guardian for the Cortex platform") | [**Cortex platform install guide**](cortex-platform/README.md) |

Each edition also has a second, optional download, `Guardian-<Edition>-Manual-Upload-v<version>.zip`, for importing the content **file by file** in the console when a pack install is not possible. Use one or the other, not both.

Each download is a single zip. Unzip it and open its `README.md`, which is that edition's install guide: the content in the pack, four ways to install it (an install script, the console's
pack upload, `demisto-sdk upload` of the pack, or item by item in the right order with where to import each item), creating the Jobs, a first run, upgrading and troubleshooting.
Adding the model provider is shared and has its own page: [Setting up the model provider](MODEL_SETUP.md) (Microsoft Foundry with a resource key or Microsoft Entra ID, Google Vertex AI,
and Cohere North on-premises with an engine where needed).

What is inside a download:

```
Guardian-<EDITION>-v<version>/
  README.md                the install guide for this platform
  pack/                    the pack, ready to install (every integration and automation is one unified YAML file)
  tools/                   install_pack.py, create_jobs.py, the job definitions (Cortex platform: also adopt_playbooks.py and the playbooks)
  integrations/            the Foundry model integration alone, one unified YAML
  docs/                    model setup, the operator runbook, the capabilities guide, an overview
  SHA256SUMS               checksums of every file; check with: shasum -a 256 -c SHA256SUMS
```

Nothing has to be built and `demisto-sdk` is not needed (it is only one of the four install methods). Building the downloads yourself: `python3 scripts/build_release.py` from a checkout
(needs `demisto-sdk` in `.venv`); it fails if a file is not unified, an item count is off, an item carries the wrong marketplace tag, or a file contains a lab address or a forbidden name.
