#!/usr/bin/python3
import logging as out
import socket
import ssl
import sys
import time
from urllib.parse import urlparse

out.basicConfig(level=out.INFO, format="[%(levelname)s] %(message)s")


class SmartClient:
    """SmartClient that returns the index page or indicated page."""
    # Shared socket, I call it session.
    __session = None
    # Combine these index names below will generate the default index page path
    # Only use if path is empty, and no 301/302
    __index_suffix_list = [".do", ".php", ".htm", ".html", ".jsp"]
    __index_name_list = ["index", "default"]
    # Raw header text list
    __header_text_list = []
    # Raw body text list
    __body_text_list = []
    # Raw body text
    __body_text = ""
    # Protocol priority
    __protocol_priority = ["https", "http"]
    # Default port
    __default_port = {"https": 443, "http": 80}
    # Protocol
    __protocol = ["h2", "http/1.1", "http/1.0"]
    # Support highest protocol
    __highest_protocol = ""
    # Support protocol
    __support_protocol = {"https": False, "http": False}
    # URL
    __url = None
    # Http code
    __status = 0
    # Protected by password
    __password_protection = False
    # Cookies
    __cookies = []
    # Javascript cookies
    __js_cookies = []

    def __init__(self, url: str):
        """Constructor that try to figure out the protocol server use.
        When url has critical error, or any connection error, it will raise error.

        :param url: URL you want to get.
        """
        # prevent incomplete url like "google.com"
        try:
            if "//" not in url[:8]:
                self.__url = urlparse("https://{}".format(url))
            else:
                self.__url = urlparse(url)
            out.info("Input URL is {}".format(url))
            # this will check port range
            __test_port_var = self.__url.port
        except ValueError as err:
            raise SyntaxError("URL is critical. {}".format(err))
        # first try https because http2 is basically over https
        # if user prefer http, then use http first
        if self.__url.scheme == "http":
            self.__protocol_priority = ["http", "https"]
        out.warning("Detecting protocol, there are some requests will be send.")
        self.__try_protocol()
        if self.__highest_protocol == "None":
            raise ConnectionError("This server does not support any http protocol.")
        out.warning("Try get cookies by fetching the given path {}. If there's 404, I will try some default path."
                    .format(self.__url.path if self.__url.path != '' else "/"))
        self.__fetch()
        # Now I have the latest page, I can get cookies from this page.
        self.__generate_cookies()
        out.warning("Summary of input URL {}".format(url))
        out.warning("=" * 80)
        out.warning("This server support highest protocol is: {}".format(self.__highest_protocol))
        out.warning("Does it support h2? {}".format("Yes" if self.__highest_protocol == "h2" else "No"))
        out.warning("Does it support https? {}".format("Yes" if self.__support_protocol["https"] else "No"))
        out.warning(
            "Does it support pure http (http/1.1)? {}".format("Yes" if self.__support_protocol["http"] else "No"))
        out.warning("Password-protected: {}".format("Yes" if self.__password_protection else "No"))
        out.warning("=" * 80)
        if self.__cookies:
            out.warning("Cookies in http header:")
            out.debug(self.__cookies)
            for c in self.__analyze_cookies():
                out.warning(c)
        else:
            out.warning("There's no cookie in header.")
        out.warning("=" * 80)
        if self.__js_cookies:
            out.warning("These javascript statements below could set cookies:")
            for j in self.__js_cookies:
                out.warning(j)
        out.warning("End")

    def __analyze_cookies(self) -> list:
        """Convert cookie list to human-readable list.

        :return: Cookie details texts in list.
        """
        __return_text_list = []
        for d in self.__cookies:
            __temp_text = "Cookie name: "
            __temp_text += list(d.keys())[0]
            __temp_text += ", value: "
            __temp_text += d[list(d.keys())[0]]
            if "expires" in d.keys():
                __temp_text += ', expire time: ' + d['expires']
            if "domain" in d.keys():
                __temp_text += ', domain: ' + d['domain'] if d['domain'] is not None else ''
            __return_text_list.append(__temp_text)
        return __return_text_list

    def __generate_cookies(self):
        """Split cookies into __header_text_list."""
        for h in self.__header_text_list:
            if "set-cookie" in h.lower():
                __temp_cookie_string = h.split(": ")[1]
                __temp_cookie_dictionary = {}
                for __temp_cookie_param in __temp_cookie_string.split("; "):
                    if "=" in __temp_cookie_param:
                        __key, __value = __temp_cookie_param.split("=", 1)
                        __temp_cookie_dictionary[__key] = __value
                    else:
                        # no need to store these cookies that not include "="
                        continue
                self.__cookies.append(__temp_cookie_dictionary)

        # These code below have not been tested because I can not find a website generate cookie from javascript
        __start_position = -1
        __start_position = self.__body_text.find("document.cookie")
        while __start_position != -1:
            __end_position = self.__body_text.find(";", __start_position)
            __temp_cookie_string = self.__body_text[__start_position: __end_position]
            __start_position = self.__body_text.find("document.cookie", __start_position + 1)
            self.__js_cookies.append(__temp_cookie_string)

    def __fetch(self):
        """Fetch URL to figure out the last page's cookies."""
        out.debug(self.__highest_protocol)
        out.debug(self.__support_protocol)
        __now_protocol = "https" if self.__support_protocol["https"] else "http"
        self.__get(__now_protocol)
        __count = 0
        while self.__status != 200:
            if __count >= 10:
                # Jump too much, maybe wrong configuration
                raise ConnectionError("Too much redirection, abort.")
            for h in self.__header_text_list:
                if "WWW-Authenticate" in h:
                    self.__password_protection = True
            if self.__status == 301 or self.__status == 302:
                # Redirect
                # first get location
                __new_location = ""
                for h in self.__header_text_list:
                    if "location" in h.lower():
                        __new_location = h.split(" ")[1]
                        break
                if __new_location == "":
                    raise ConnectionError("Server response 301/302 but no new location was gave.")
                # assume that this url from server is reliable
                out.warning("Meeting {} , Fetching new location: {}".format(self.__status, __new_location))
                if "//" not in __new_location[:8]:
                    # default http, not influence protocol that __try_protocol detected
                    self.__url = urlparse("http://{}".format(__new_location))
                else:
                    self.__url = urlparse(__new_location)
                if self.__url.scheme:
                    self.__get(self.__url.scheme)
                    self.__support_protocol[self.__url.scheme] = True
            if self.__status == 404:
                # this path not found, check if count is 0.
                if __count == 0:
                    # try those default path
                    for __filename in self.__index_name_list:
                        for __suffix in self.__index_suffix_list:
                            self.__get(__now_protocol, "/{}{}".format(__filename, __suffix))
                            out.debug(self.__status)
                            if self.__status != 404:
                                self.__url = urlparse("{}://{}/{}{}"
                                                      .format(self.__url.scheme, self.__url.netloc,
                                                              __filename, __suffix))
                                __count += 1
                else:
                    # it is just server configuration error, ignore
                    pass
            if self.__status == 401:
                # No need to continue
                self.__password_protection = True
                break
            __count += 1

    def __new_session(self, protocol: str):
        """Create new http/https socket.

        :param protocol: "http" or "https", socket will generate according this.
        """
        if self.__session:
            self.__session.close()
        if protocol == "https":
            context = ssl.create_default_context()
            # just priority, so add h2 in it, once it supports h2, it will use
            context.set_alpn_protocols(self.__protocol)
            self.__session = context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                                                 server_hostname=self.__url.hostname)
        else:
            self.__session = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.__session.settimeout(5)
            if self.__url.port:
                self.__session.connect((self.__url.hostname, self.__url.port))
            else:
                self.__session.connect((self.__url.hostname, self.__default_port[protocol]))
            self.__session.settimeout(None)
        except (socket.error, ssl.CertificateError, ssl.SSLError, socket.timeout):
            raise ConnectionError("Cannot open socket, maybe network issue.")

    def __get(self, protocol: str, path=""):
        """Send get header and receive, which means full steps of http get.

        :param protocol: "http" or "https", will use this to create socket.
        :param path: Optional, if exists then use that path, not self.__url.path.
        """
        try:
            self.__new_session(protocol)
        except Exception as err:
            raise err
        __header = []
        if path == "":
            if self.__url.path == "" or self.__url.path == "/":
                # try / first
                __path = "/"
            else:
                __path = self.__url.path
        else:
            __path = path
        out.debug("{}://{}/{}".format(protocol, self.__url.hostname, path))
        # Package header
        __header.append("GET {} HTTP/1.1".format(__path))
        __header.append("Host: {}".format(self.__url.hostname))
        __header.append("Accept: */*")
        __header.append("User-agent: SmartClient/0.0.1")
        if protocol == "http":
            __header.append("Connection: close")
            __header.append("Upgrade: h2c")
        else:
            __header.append("Connection: close")
        self.__send(__header)
        self.__receive()

    def __send(self, requests: list):
        """Send request line by line in request list.

        :param requests: Request list include headers, actually can include body.
        """
        out.info("Sending Requests:")
        out.info("---Request Begin---")
        for request in requests:
            out.info(request)
            self.__session.sendall(request.encode())
            self.__session.sendall("\r\n".encode())
        self.__session.sendall("\r\n".encode())
        out.info("---Request End---")

    def __receive(self):
        """Receive lines and split with "\r\n"."""
        try:
            __response = ""
            __timeout_start = None
            while True:
                __temp_recv = self.__session.recv(8192)
                if __temp_recv:
                    __response += __temp_recv.decode(errors='ignore')
                else:
                    if not __timeout_start:
                        __timeout_start = time.time()
                if __timeout_start:
                    if __temp_recv:
                        if time.time() - __timeout_start >= 1:
                            continue
                    else:
                        if time.time() - __timeout_start >= 2:
                            break
            out.info('---Respond Header Begin---')
            self.__header_text_list = __response.split("\r\n\r\n")[0].split('\r\n')
            for h in self.__header_text_list:
                out.info(h)
            out.info('---Respond Header End---')
            if len(__response.split("\r\n\r\n")) > 1:
                out.info('---Respond Body Begin---')
                for bs in __response.split("\r\n\r\n")[1:]:
                    self.__body_text += bs
                    for b in bs.split("\n"):
                        self.__body_text_list.append(b)
                        out.info(b)
                out.info('---Respond Body End---')
            else:
                out.warning("There's no respond body.")
            # maybe cause error in converting to int
            self.__status = int(self.__header_text_list[0].split(" ")[1])
            out.debug(self.__status)
        except Exception as err:
            raise err

    def __try_protocol(self):
        """Test protocol."""
        for p in self.__protocol_priority:
            try:
                self.__get(p)
            except Exception as err:
                out.warning("Protocol {} not support, reason: {}".format(p, err))
                self.__support_protocol[p] = False
            else:
                self.__support_protocol[p] = True
        if self.__support_protocol["https"]:
            self.__new_session("https")
            if self.__session.selected_alpn_protocol() == "h2":
                self.__highest_protocol = "h2"
            else:
                self.__highest_protocol = "https"
        elif self.__support_protocol["http"]:
            self.__highest_protocol = "http"
        else:
            self.__highest_protocol = "None"

    def get_protocol_support(self) -> dict:
        """Get variable __support_protocol, this var is a dictionary of protocol that server support.

        :return: A dictionary of protocol that server support, like {"http": True. "https": True}
        """
        return self.__support_protocol

    def get_highest_protocol(self) -> str:
        """Get variable __highest_protocol, this var is a string of the highest protocol server support.

        :return: A string of the highest protocol server support, maybe "h2", "https", "http" or "None".
        """
        return self.__highest_protocol


if __name__ == "__main__":
    try:
        SmartClient(sys.argv[1])
    except SyntaxError as e:
        out.error("URL mistake: {}".format(e))
    except ConnectionError as e:
        out.error(e)
    except IndexError as e:
        out.error("Command wrong. [{}] Usage: python3 SmartClient.py [URL]".format(e))
    else:
        exit(0)
    exit(-1)
