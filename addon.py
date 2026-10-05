import mitmproxy
import mitmproxy_rs
import tkinter as tk
from tkinter import ttk

import subprocess
import threading
import asyncio
import aiohttp
import time
import io
import os

from PIL import Image, ImageTk
import requests
import json
import qrcode

import gzip
import zlib as deflate
import brotli as br
import zstandard as zstd

with open("defaults.json", "r") as defaults_json:
  defaults = json.loads(defaults_json.read())
  ENABLE_GUI = defaults["ENABLE_GUI"]
  FORCE_MAX_COMPRESSION = defaults["FORCE_MAX_COMPRESSION"]
  IMAGE_QUALITY = defaults["IMAGE_QUALITY"]
  USE_AVIF = defaults["USE_AVIF"]
  USE_SPECULATIVE_CACHE = defaults["USE_SPECULATIVE_CACHE"]
  SPECULATIVE_CACHE_MAX_ENTRIES = defaults["SPECULATIVE_CACHE_MAX_ENTRIES"]
  CLEAR_HTTP_ERRORS = defaults["CLEAR_HTTP_ERRORS"]
  BLOCK_ADS = defaults["BLOCK_ADS"]
  ENABLE_DEBUG = defaults["ENABLE_DEBUG"]

def start_gui():
  if not ENABLE_GUI: return

  global gui_root, frame_root
  gui_root = tk.Tk()
  gui_root.title("Arachnidium web proxy")

  frame_root = ttk.Frame(gui_root)
  frame_root.pack(fill="both", expand=True, padx=100, pady=30)

  gui_root.tk.call("source", "theme/azure.tcl")
  gui_root.tk.call("set_theme", "light")

  ttk.Label(frame_root, name="saved-label", text="Data saved: 0B", font=("Helvetica", 14)).pack()
  ttk.Label(frame_root, name="used-label", text="Data used: 0B", font=("Helvetica", 14)).pack(pady=15)

  tk_IMAGE_QUALITY = tk.IntVar(value=IMAGE_QUALITY)
  tk_FORCE_MAX_COMPRESSION = tk.BooleanVar(value=FORCE_MAX_COMPRESSION)
  tk_USE_AVIF = tk.BooleanVar(value=USE_AVIF)
  tk_USE_SPECULATIVE_CACHE = tk.BooleanVar(value=USE_SPECULATIVE_CACHE)
  tk_CLEAR_HTTP_ERRORS = tk.BooleanVar(value=CLEAR_HTTP_ERRORS)
  tk_BLOCK_ADS = tk.BooleanVar(value=BLOCK_ADS)
  tk_ENABLE_DEBUG = tk.BooleanVar(value=ENABLE_DEBUG)

  image_quality_label = ttk.Label(frame_root, text="Image Quality (" + str(IMAGE_QUALITY) + ")")
  image_quality_label.pack()

  def update_settings(_=0):
    global IMAGE_QUALITY, FORCE_MAX_COMPRESSION, USE_AVIF, USE_SPECULATIVE_CACHE, CLEAR_HTTP_ERRORS, BLOCK_ADS, ENABLE_DEBUG
    IMAGE_QUALITY=tk_IMAGE_QUALITY.get()
    FORCE_MAX_COMPRESSION=tk_FORCE_MAX_COMPRESSION.get()
    USE_AVIF=tk_USE_AVIF.get()
    USE_SPECULATIVE_CACHE=tk_USE_SPECULATIVE_CACHE.get()
    CLEAR_HTTP_ERRORS=tk_CLEAR_HTTP_ERRORS.get()
    BLOCK_ADS=tk_BLOCK_ADS.get()
    ENABLE_DEBUG=tk_ENABLE_DEBUG.get()
    image_quality_label.config(text="Image Quality (" + str(IMAGE_QUALITY) + ")")

  ttk.Scale(frame_root, from_=0, to=100, orient="horizontal", variable=tk_IMAGE_QUALITY, command=update_settings).pack()
  ttk.Checkbutton(frame_root, text="Force Max Compression", variable=tk_FORCE_MAX_COMPRESSION, command=update_settings).pack()
  ttk.Checkbutton(frame_root, text="Use AVIF Images", variable=tk_USE_AVIF, command=update_settings).pack()
  ttk.Checkbutton(frame_root, text="Speculative Caching", variable=tk_USE_SPECULATIVE_CACHE, command=update_settings).pack()
  ttk.Checkbutton(frame_root, text="Clear HTTP Error Body", variable=tk_CLEAR_HTTP_ERRORS, command=update_settings).pack()
  ttk.Checkbutton(frame_root, text="Block Ads", variable=tk_BLOCK_ADS, command=update_settings).pack()
  ttk.Checkbutton(frame_root, text="Debug Mode", variable=tk_ENABLE_DEBUG, command=update_settings).pack()

  def open_qrcode_window():
    new_window = tk.Toplevel(frame_root)
    new_window.title("WireGuard Configuration QR Code")
    new_window.geometry("300x300")
    with open("wireguard.cfg", "r") as wg_config_file:
      config = wg_config_file.read()
      config_qr = qrcode.make(config)
      config_qr = config_qr.resize((300, 300))
      qr_img = ImageTk.PhotoImage(config_qr)
      panel = tk.Label(new_window, image=qr_img)
      panel.img = qr_img
      panel.pack()

  ttk.Button(frame_root, text="Show WireGuard QR Code", command=open_qrcode_window).pack(pady=(10, 0))

  def on_window_close():
    mitmproxy.ctx.master.shutdown()

  gui_root.protocol("WM_DELETE_WINDOW", on_window_close)

  gui_root.mainloop()

speculative_cache = {}

async def do_async_http_request(url: str, headers: mitmproxy.http.Headers):
  async with aiohttp.ClientSession(headers=headers) as session:
    async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as response:
      try:
        body = await response.read()
        return (body, response)
      except:
        return None

def check_dns_blocklist(host: str):
  global DNS_BLOCKLIST
  return any((host == s or host.endswith("." + s)) for s in DNS_BLOCKLIST)

async def request(flow: mitmproxy.http.HTTPFlow) -> None:
  # Reject hosts that don't pass the DNS blocklist
  if BLOCK_ADS:
    if check_dns_blocklist(flow.request.pretty_host):
      flow.response = mitmproxy.http.Response.make(status_code=403)
      return

  if not flow.request.pretty_url in speculative_cache: return
  if ENABLE_DEBUG: print("Cache hit:", flow.request.pretty_url)

  # Do not process mitmproxy certificate installation page
  if flow.request.pretty_host == "mitm.it":
    return

  # Retrieve cached HTTP response, await if necessary.
  (cached_response, timestamp) = speculative_cache[flow.request.pretty_url]
  (body, res) = await cached_response
  # Remove it from the cache.
  del speculative_cache[flow.request.pretty_url]
  if not cached_response: return

  headers = mitmproxy.http.Headers()
  for header in res.headers:
    headers[header] = res.headers[header]

  # Forge a fake flow response to make it compatible with optimization function.
  flow.response = mitmproxy.http.Response.make(
    status_code=200,
    content=body,
    headers=headers
  )
  flow.is_replay = "request"

  # Run the forged flow through the response handler to perform optimization.
  response(flow)

def convert_webp(data: bytes) -> bytes:
  image = Image.open(io.BytesIO(data))
  output = io.BytesIO()
  image.save(
    output,
    format="WEBP",
    lossless=(IMAGE_QUALITY == 100),
    quality=IMAGE_QUALITY,
    alpha_quality=IMAGE_QUALITY,
    method=6,
    save_all=True
  )
  return output.getvalue()

def convert_avif(data: bytes) -> bytes:
  image = Image.open(io.BytesIO(data))
  output = io.BytesIO()
  image.save(
    output,
    format="AVIF",
    # AVIF needs a higher quality value than WebP for similar visual quality,
    # so map IMAGE_QUALITY onto a roughly equivalent AVIF quality (by SSIM).
    quality=round(24 + 0.6 * IMAGE_QUALITY),
    # Speed 8 is usually faster than WebP's method 6 and still produces smaller
    # files. Lower speeds compress a bit better, but are much slower.
    speed=8,
    save_all=True
  )
  return output.getvalue()

# I'm not proud that all of this is externalized to Bun, but the JavaScript
# ecosystem is far better at web stuff. Who could've guessed!
def process_html(code: str, url: str) -> tuple[str, str]:
  api_response = requests.post(
    "http://localhost:3000/api/minify/html",
    data=json.dumps({ "code": code, "url": url })
  )
  data = json.loads(api_response.text)
  return (data["code"], data["links"])
def do_minify_css(code: str) -> str:
  api_response = requests.post("http://localhost:3000/api/minify/css", data=code)
  return api_response.text
def do_minify_js(code: str) -> str:
  api_response = requests.post("http://localhost:3000/api/minify/js", data=code)
  return api_response.text
def do_minify_svg(code: str) -> str:
  api_response = requests.post("http://localhost:3000/api/minify/svg", data=code)
  return api_response.text

def do_minify_json(code: str) -> str:
  try:
    return json.dumps(
      json.loads(code),
      separators=(',', ':'),
      check_circular=False
    )
  except:
    return code

def sizeof_fmt(num, suffix="B"):
  for unit in ("", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"):
    if abs(num) < 1024.0:
      return f"{num:3.1f}{unit}{suffix}"
    num /= 1024.0
  return f"{num:.1f}Yi{suffix}"

def count_savings(size_before: int, size_after: int) -> None:
  just_saved = size_before - size_after
  if not "data_saved" in globals():
    global data_saved, data_used
    data_saved = 0
    data_used = 0
  data_saved += just_saved
  data_used += size_before
  data_saved_fmt = sizeof_fmt(data_saved)
  data_used_fmt = sizeof_fmt(data_used)

  if ENABLE_GUI:
    global gui_root, frame_root
    gui_root.after(0, lambda: {
      frame_root.children["saved-label"].config(text=("Data saved: " + data_saved_fmt)),
      frame_root.children["used-label"].config(text=("Data used: " + data_used_fmt))
    })

  if ENABLE_DEBUG:
    print("JUST SAVED: ", sizeof_fmt(just_saved))
    print("TOTAL SAVED:", sizeof_fmt(data_saved))

def response(flow: mitmproxy.http.HTTPFlow) -> None:
  if not (flow.response and flow.response.content):
    return

  size_before = len(flow.response.raw_content)

  # Clear the body of responses that don't use it.
  if (flow.response.status_code == 301 or # Moved Permanently
      flow.response.status_code == 302 or # Found (Moved Temporarily)
      flow.response.status_code == 304 or # Not Modified
      flow.response.status_code == 307 or # Temporary Redirect
      flow.response.status_code == 308 or # Permanent Redirect
      (CLEAR_HTTP_ERRORS and
        # Clear most error bodies, keeping only "Not Found" and "Gone".
        # Some websites generate meaningful content for missing pages.
        flow.response.status_code >= 400 and
        flow.response.status_code != 404 and
        flow.response.status_code != 410
      )
    ):
    flow.response.headers["content-length"] = "0"
    flow.response.raw_content = b""
    if "content-encoding" in flow.response.headers:
      del flow.response.headers["content-encoding"]
    return count_savings(size_before, len(flow.response.raw_content))

  content_type = flow.response.headers.get("content-type") or "application/octet-stream"
  if ENABLE_DEBUG: print(content_type)
  charset = "utf-8"
  if "charset=" in content_type:
    charset = content_type.split("charset=")[1].split(";")[0]

  # Convert common image formats to WebP.
  # Images are handled first, because they don't require additional HTTP compression.
  if (content_type.startswith("image/png")  or
      content_type.startswith("image/jpeg") or
      content_type.startswith("image/webp") or
      content_type.startswith("image/gif")  or
      content_type.startswith("image/vnd.microsoft.icon")):
    # Prefer AVIF when the client advertises support for it. Lossless output
    # (quality 100) stays WebP, as does anything AVIF fails to encode.
    output = None
    accept = flow.request.headers.get("accept") or ""
    if USE_AVIF and IMAGE_QUALITY < 100 and "image/avif" in accept:
      try:
        output = convert_avif(flow.response.content)
        flow.response.headers["content-type"] = "image/avif"
      except Exception as e:
        if ENABLE_DEBUG: print("AVIF conversion failed, using WebP:", e)
    if output is None:
      output = convert_webp(flow.response.content)
      flow.response.headers["content-type"] = "image/webp"
    flow.response.raw_content = output
    if "content-encoding" in flow.response.headers:
      del flow.response.headers["content-encoding"]
    flow.response.headers["content-length"] = str(len(flow.response.raw_content))
    return count_savings(size_before, len(flow.response.raw_content))

  accepted_encodings = flow.request.headers.get("accept-encoding") or ""
  accepted_encodings = list(map(lambda a : a.strip(), accepted_encodings.split(",")))

  # If the client doesn't support anything better than gzip, we can read
  # the compression level used by the origin and skip minification if
  # max compression was used. This is usually more efficient than minifying
  # and recompressing, but only if the client's best algorithm is gzip,
  # and only if FORCE_MAX_COMPRESSION is False.
  if content_type.startswith("text/") and not FORCE_MAX_COMPRESSION:
    compression = flow.response.headers.get("content-encoding")
    if compression == "gzip" and not any(i in accepted_encodings for i in ["br", "zstd"]):
      # This flag gives us a loose indication of the compression level:
      # 2 = Maximum compression
      # 4 = Minimum compression
      # 0 = Unknown/default
      # https://en.wikipedia.org/wiki/Gzip#File_structure
      extra_flags = flow.response.raw_content[8]
      if extra_flags & 2:
        return count_savings(size_before, len(flow.response.raw_content))

  use_max_compression = FORCE_MAX_COMPRESSION
  is_binary_data = content_type.startswith("application/") or content_type.startswith("image/")
  speculated_links = []

  # Minify source files.
  if content_type.startswith("text/html"):
    (output, speculated_links) = process_html(flow.response.content.decode(charset), flow.request.pretty_url)
    output = output.encode(charset)
    use_max_compression = True
  elif content_type.startswith("text/css"):
    output = do_minify_css(flow.response.content.decode(charset)).encode(charset)
  elif content_type.startswith("text/javascript"):
    output = do_minify_js(flow.response.content.decode(charset)).encode(charset)
  elif content_type.startswith("application/json"):
    output = do_minify_json(flow.response.content.decode(charset)).encode(charset)
    is_binary_data = False
  elif content_type.startswith("image/svg"):
    output = do_minify_svg(flow.response.content.decode(charset)).encode(charset)
    is_binary_data = False
  else:
    output = flow.response.content

  # Create async tasks for speculative caching, remove old entries from cache.
  if USE_SPECULATIVE_CACHE and not flow.is_replay:
    for link in speculated_links:
      if ENABLE_DEBUG: print("Caching", link)
      task = asyncio.create_task(do_async_http_request(link, flow.request.headers))
      timestamp = time.time()
      if len(speculative_cache) >= SPECULATIVE_CACHE_MAX_ENTRIES:
        oldest_link = None
        oldest_timestamp = timestamp
        for curr_link, curr_val in speculative_cache.items():
          curr_timestamp = curr_val[1]
          if curr_timestamp < oldest_timestamp:
            oldest_timestamp = curr_timestamp
            oldest_link = curr_link
        if oldest_link:
          del speculative_cache[oldest_link]
      speculative_cache[link] = (task, timestamp)

  # Recompress using best compression supported by the client.
  raw_output = output
  encoding = "identity"

  if ENABLE_DEBUG:
    print("Algorithm comparison:")
    start = time.time()
    print("  br:", sizeof_fmt(len(flow.response.raw_content) - len(br.compress(output, br.MODE_GENERIC, 11 if use_max_compression else 4))), time.time() - start)
    start = time.time()
    print("  gzip:", sizeof_fmt(len(flow.response.raw_content) - len(gzip.compress(output, 9 if use_max_compression else 6))), time.time() - start)
    start = time.time()
    print("  zstd:", sizeof_fmt(len(flow.response.raw_content) - len(zstd.compress(output, 22 if use_max_compression else 12))), time.time() - start)
    start = time.time()
    print("  deflate:", sizeof_fmt(len(flow.response.raw_content) - len(deflate.compress(output, 9 if use_max_compression else 6))), time.time() - start)

  # Compression algorithms roughly sorted from best to worst. For binary
  # data, Brotli is only used if no other algorithm is supportd.
  if "br" in accepted_encodings and (not is_binary_data or accepted_encodings == ["br"]):
    mode = br.MODE_GENERIC
    if content_type.startswith("text/"): mode = br.MODE_TEXT
    elif content_type.startswith("font/"): mode = br.MODE_FONT
    raw_output = br.compress(output, mode, 11 if use_max_compression else 4)
    encoding = "br"
  elif "gzip" in accepted_encodings:
    raw_output = gzip.compress(output, 9 if use_max_compression else 6)
    encoding = "gzip"
  elif "zstd" in accepted_encodings:
    raw_output = zstd.compress(output, 22 if use_max_compression else 12)
    encoding = "zstd"
  # This zlib library seems to be faster than gzip, but zlib is reportedly
  # "unreliable" and "unfavorable" in modern HTTP. Maybe wrapping it in a
  # gzip container ourselves might be a good idea?
  elif "deflate" in accepted_encodings:
    raw_output = deflate.compress(output, 9 if use_max_compression else 6)
    encoding = "deflate"

  if len(raw_output) < len(flow.response.raw_content):
    flow.response.headers["content-length"] = str(len(raw_output))
    flow.response.headers["content-encoding"] = encoding
    flow.response.raw_content = raw_output
  elif ENABLE_DEBUG:
    print("SKIPPING, RECOMPRESSED OUTPUT IS LARGER:", len(raw_output), ">", len(flow.response.raw_content))
    print("Server using", flow.response.headers.get("content-encoding"), "we're using", encoding)

  return count_savings(size_before, len(flow.response.raw_content))

# Block ads via DNS blocklist
def dns_request(flow: mitmproxy.dns.DNSFlow) -> None:
  if not flow.request.question: return

  # Reject DNS requests that don't pass the blocklist
  if BLOCK_ADS:
    if check_dns_blocklist(str(flow.request.question)):
      flow.response = flow.request.fail(mitmproxy.dns.response_codes.NXDOMAIN)

def load(loader: mitmproxy.addonmanager.Loader):
  if ENABLE_GUI:
    gui_thread = threading.Thread(target=start_gui, daemon=True)
    gui_thread.start()

  # Start Bun API
  bun_binary_name = "bun-api/bun" if os.name == "posix" else "bun-api/bun.exe"
  if os.path.exists(bun_binary_name):
    global bun_api_process
    bun_api_process = subprocess.Popen([bun_binary_name, "run", "bun-api/index.ts"])
  else:
    print("Warning: Could not find Bun API binary - please start it manually.")

  # Generate WireGuard config
  wan_ip_req = requests.get("https://api.ipify.org")
  if wan_ip_req.status_code != 200 or not wan_ip_req.text:
    wan_ip_req = requests.get("https://api.seeip.org")
  wan_ip = wan_ip_req.text
  with open("wg-keys.json", "r") as keys_file:
    wg_keys = json.loads(keys_file.read())
    config = f"""\
# This file was automatically generated.
# To change keys, edit `wg-keys.json` instead.

[Interface]
PrivateKey = {wg_keys["client_key"]}
Address = 10.0.0.1/32
DNS = 10.0.0.53

[Peer]
PublicKey = {mitmproxy_rs.wireguard.pubkey(wg_keys["server_key"])}
AllowedIPs = 0.0.0.0/0
Endpoint = {wan_ip}:51820"""
    # Write config to file
    with open("wireguard.cfg", "w") as config_file:
      config_file.write(config)

  # Download DNS blocklist
  global DNS_BLOCKLIST
  DNS_BLOCKLIST = requests.get("https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro-onlydomains.txt").text
  DNS_BLOCKLIST = DNS_BLOCKLIST.split("\n")
  DNS_BLOCKLIST = list(map(lambda s: s.strip(), DNS_BLOCKLIST))
  DNS_BLOCKLIST = list(filter(lambda s: not s.startswith("#"), DNS_BLOCKLIST))

def done():
  global ENABLE_GUI, gui_root
  if ENABLE_GUI and "gui_root" in globals() and gui_root:
    print("destroying")
    gui_root.after(0, lambda: {
      gui_root.destroy()
    })
  global bun_api_process
  if "bun_api_process" in globals():
    bun_api_process.terminate()
