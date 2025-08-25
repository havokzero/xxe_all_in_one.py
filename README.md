
# XXE All-in-One Tester

An interactive tool that helps you **find and exploit XML External Entity (XXE) bugs**.  
It builds the right payloads for many situations, tries different ways to deliver them, and shows you clear results.

> ⚠️ Disclaimer  
> Use only with permission, for learning and authorized testing. You are responsible for how you use this.

---

## What it does (plain language)

- Sends XML payloads that read files (like /etc/passwd) or make the target call back to you (OOB).
- Tries multiple delivery methods (POST body, URL parameter, form field, file upload).
- Tweaks payloads automatically (small changes that bypass picky parsers/filters).
- Can host its own “evil DTD” and a simple HTTP listener to catch callbacks.
- Shows which attempts worked best and saves responses so you can review them.

---

## Key features

- Attack modes: file read (file://), blind OOB HTTP, DNS stub, SSRF, php://filter (base64), expect:// (lab only), external DTD with parameter entities, custom XML.
- Transports: POST body, GET param, POST form param, multipart upload.
- Mini-fuzzer: rotates param/field names and Content-Type; optional SOAP auto-wrapper.
- Payload mutators: case/whitespace/protocol tweaks.
- Auto-decode previews: tries to decode base64 and gzip to show readable output.
- Concurrency + retry backoff.
- “Best attempts” scoring table.
- Autosave to captures/ and per-target profiles in profiles/.

---

## Installation

1) Clone the repo  
    git clone https://github.com/havokzero/xxe_all_in_one.py.git  
    cd xxe_all_in_one.py

2) Create a virtual environment (recommended)  
    python3 -m venv venv  
    source venv/bin/activate    (on Windows: venv\Scripts\activate)

3) Install the only dependency  
    pip install requests

---

## Usage (step by step)

Run the tool  
    python xxe_all_in_one.py

You’ll be prompted for simple choices:
- Target URL (example: http://127.0.0.1:8080/import)
- Transport method (POST body / GET param / POST form / file upload)
- XXE mode (file read, OOB, SSRF, php filter, external DTD, etc.)
- Optional: enable the mini fuzzer (tries multiple params/content-types), SOAP wrapper, concurrency, and retries
- Headers/cookies/proxy if needed

Tip: For blind XXE, let it start the built-in HTTP listener; you’ll see callbacks printed.  
For external DTD, it can host /evil.dtd for you and automatically reassemble base64 chunks.

What you get after a run:
- A short “Best attempts” table (status, time, size, keyword hits).
- Responses saved under captures/ so you can open them later.
- Any callbacks it caught printed on screen (and base64 exfil reassembled when possible).

---

## Options you’ll see

- Transports: POST body, GET param, POST form param, multipart upload (file field + filename).
- Content-Types: application/xml, text/xml, application/soap+xml (SOAP wrapper optional).
- Modes: file read, HTTP OOB, DNS stub, SSRF, php://filter (base64), expect:// (labs), external DTD (with base64 exfil), custom XML.
- Fuzzing: rotate common parameter and field names automatically.
- Mutators: small payload variations to slip past brittle checks.
- Concurrency & retries: send small bursts with backoff if something fails.
- Profiles: save/load your settings per target (profiles/NAME.json).

---

## Project layout

- xxe_all_in_one.py  → main script  
- captures/          → saved responses  
- profiles/          → saved per-target settings

---

## Friendly notes

- Start simple: file read on /etc/hostname. If nothing shows, try blind OOB.
- If the app wants uploads, pick “multipart” and let the fuzzer rotate common field names.
- If you see base64 blobs, the preview often decodes them for you; the raw body is still saved.
- Keep runs small and targeted; the fuzzer is helpful, but be mindful of rate limits.

---

## License

MIT
