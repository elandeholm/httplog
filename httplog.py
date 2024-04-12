#!/usr/bin/env python
#
# logs browser activity
#
# starting point was a script called contrib/httpdump.py
#

import time
import base64
import bs4
import sys

from mitmproxy import ctx
from mitmproxy import http

class HTTPLog:
    # circa minutes since epoch is fine
    # we don't need a massive xxxxxxxxxxx.yyyyyyyy time code on every line

    def minutes(self) -> int:
        return round(time.time() / 60)

    # base64 encode a utf-8 string which may get truncated
    # truncation is signalled by prefixing a backslash before encoding
    # note that this is not a guarantee on the length of the encoding,
    # since there could be multibyte characters in there
    # if you have a str that may begin with a backslash, this is not
    # the unambiguous encoding you want
 
    def _b64(self, s: str, max_len: int) -> str:
        if len(s) > max_len:
            s = '\\' + s[:max_len-1]

        s_bytes = bytes(s, encoding="utf-8")
        return str(base64.b64encode(s_bytes))[2:-1]

    def load(self, loader) -> None:
        loader.add_option(
            # this is the content type whitelist for
            # parsing response text using BS4, which
            # is done to extract the resource's "title"
            # I tried a blacklist approach first and that
            # was stupid, because servers basically put
            # anything in this header
            # servers also cram random "parameters" in here
            # using WS and semi-colons, so we split and trim
            # before matching, eg.
            # "Content-type: text/html    ; Ya like jazz?"
            # is going to match
            name="bs4_ct_wl",
            typespec=set,
            default=set([
                "text/html"
                ]),
            help="content type whitelist for BeautifulSoup",
        )
        loader.add_option(
            name="open_browser",
            typespec=bool,
            default=False,
            help="open integrated browser at start",
        )
        # set of blacklisted hosts that we may not want to log
        # ie. analytics, scripts or cdn garbage. only 90% or so
        # of the traffic...
        # format is one host per line, in lowercase
        # A lowercased pretty_host of "goog.le" isn't going to match "Goog.Le"
        blacklisted_hosts = set()
        try:
            with open("host_blacklist", "r") as hbl:
                for hostline in hbl.readlines():
                    blacklisted_hosts.add(hostline.strip().lower())
        except FileNotFoundError:
            pass # we don't care if the blacklist doesn't exist            
        loader.add_option(
            name="host_blacklist",
            typespec=set,
            default=blacklisted_hosts,
            help="set of blacklisted hosts",
        )

        self.valid_request_methods = set([
            "HEAD", "GET", "PUT", "POST", "OPTIONS",
            "DELETE", "CONNECT", "TRACE", "PATCH"
            ])

        self.logfile   = open("http.log", "a", buffering=1)
        self.debugfile = open("debug.log", "a", buffering=1)

    def debug(self, message: str, url: str = "", host: str = "") -> None:
        # vain effort to make the debug log somewhat machine readable
        # if url or message contain special characters, we lose
        # it's fine though, this is meant to be read by an ape

        urlf = ""
        if url is not None and url != "":
            urlf = f", url={url}"

        hostf = ""
        if host is not None and host != "":
            hostf = f", host={host}"

        message.replace("\n", "\\n")
        print(str(self.minutes()) + " - " + message + hostf + urlf, file=self.debugfile)

    def running(self) -> None:
        if ctx.options.open_browser:
            ctx.master.commands.call("browser.start")

    def configure(self, updated : bool) -> None:
        if updated:
            self.debug("configuration updated")
            self.debug(str(ctx.options.host_blacklist))

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.request.pretty_host.lower() in ctx.options.host_blacklist:
            #self.debug("blacklisted host", host=flow.request.pretty_host)
            # just return early if the host is blacklisted
            return

        self.log(flow)

    def filter_request_method(self, request_method: str, url: str) -> str:
        # remove leading & trailing WS, uppercase,
        # remove non alnum and truncate if too long

        request_method = request_method.strip().upper()
        request_method = ''.join(filter(str.isalnum, request_method)) 
        request_method = request_method[:10]

        if not request_method in self.valid_request_methods:
            self.debug(f"invalid request metod: {request_method}", url=url)

        return request_method

    def filter_status_code(self, status_code: str, url: str) -> str:
        # remove leading & trailing WS, uppercase,
        # remove non alnum and truncate if too long

        status_code = status_code.strip().upper()
        status_code = ''.join(filter(str.isalnum, status_code)) 
        status_code = status_code[:10]

        try:
            numeric_code = int(status_code)
            status_code = str(numeric_code)
        except Exception as e:
            self.debug(f"invalid status code: {status_code}", url=url)
            status_code = "INVALID"

        return status_code

    def filter_content_type(self, content_type: str, url: str) -> str:
        # split, reject/trunc, join

        try:
            super_type, sub_type, *_ = (content_type + "//").split("/", 2)
        except Exception as e:
            listan = (content_type + "//").split("/", 2)
            self.debug(str(e) + f" {listan}", url=url)
            return "katt/gurka"

        # remove leading & trailing WS, uppercase,
        # remove non alnum and truncate if too long

        super_type = super_type.strip().lower()
        super_type = ''.join(filter(str.isalnum, super_type)) 
        super_type = super_type[:10]

        # remove leading & trailing WS, uppercase,
        # remove non alnum and truncate if too long

        sub_type = sub_type.strip().lower()
        sub_type = ''.join(filter(str.isalnum, sub_type)) 
        sub_type = sub_type[:10]

        return super_type + "/" + sub_type

    def log(self, flow: http.HTTPFlow) -> None:
        url = flow.request.pretty_url
        request_method = flow.request.method
        status_code = None

        content_type = ""
        title = ""

        have_response = False
        if flow.response:
            have_response = True

        have_content_type = False
        if have_response:
            if "content-type" in flow.response.headers:
                ct = flow.response.headers["content-type"]
                have_content_type = True
                content_type = ct.split(";")[0].lower()
            status_code = str(flow.response.status_code)

        # these are here to ensure we don't log garbage data
        # that could make the logfile non machine readable

        request_method = self.filter_request_method(request_method, url)
        status_code = self.filter_status_code(status_code, url)
        content_type = self.filter_content_type(content_type, url)

        # attempt to parse title when appropriate

        have_title = False
        if have_content_type and content_type in ctx.options.bs4_ct_wl:
            if have_response:
                text = flow.response.text

                # this is to catch BS4 warnings
                # so I can see what requests/texts/encodings
                # triggers them, in order to code around any
                # issues, and/or add a host to the blacklist

                import warnings
                warnings.simplefilter("error")

                try:
                    bs = bs4.BeautifulSoup(text, 'html.parser')
                    if bs.title is None:
                        # This is a kludge. Youtube generates so many of these
                        # and they clog up the debug and the log

                        if flow.request.pretty_host == "www.youtube.com":
                            return
                        self.debug(f"bs4 <None> title. ct={content_type}",
                            host=flow.request.pretty_host)
                    else:
                        t = bs.title.string
                        if t is None:
                          self.debug(f"bs4 no title string: ct={content_type}", url=url)
                        else:
                            title = t
                            have_title = True
                except Exception as e:
                    e_info = str(e)[:100]
                    self.debug(f"bs4 failed. e={e_info}, ct={content_type}", url=url)

                # TODO: While "ignore" "works", it's really quite
                # sketchy. What I WANT to do is to restore warnings
                # to its state before I did simplefilter("error")

                # I'm sure the right way is to use a context manager
                # I'll just remove the warnings->errors once I've ironed
                # out most of the issues with BS4 parsing of random data

                warnings.simplefilter("ignore")

        haves = "{}{}{}".format(int(have_response), int(have_content_type), int(have_title))

        # These are base64 encoded and truncated to ensure machine readability

        b64_url = self._b64(url, max_len=200) # TODO: make max_len here an option
        b64_title = self._b64(title, max_len=100) # same

        minutes = str(self.minutes())

        logline = f"{minutes}:{haves}:{request_method}:{status_code}:{content_type}:{b64_url}:{b64_title}"

        print(logline, file=self.logfile)

addons = [HTTPLog()] # hey, that's us!
