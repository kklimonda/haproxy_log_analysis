# -*- coding: utf-8 -*-
from datetime import datetime

import enum
import re


# Example log line, to understand the regex below (truncated to fit into
# 80 chars):
#
# Dec  9 13:01:26 localhost haproxy[28029]: 127.0.0.1:39759
# [09/Dec/2013:12:59:46.633] loadbalancer default/instance8
# 0/51536/1/48082/99627 200 83285 - - ---- 87/87/87/1/0 0/67
# {77.24.148.74} "GET /path/to/image HTTP/1.1"

HAPROXY_LINE_REGEX = re.compile(
    # Dec  9 13:01:26 localhost haproxy[28029]:
    # ignore the syslog prefix if present
    r'(\A.*\]:\s+)?'
    # 127.0.0.1:39759
    r'(?P<client_ip>[a-fA-F\d+\.:]+):(?P<client_port>\d+)\s+'
    # [09/Dec/2013:12:59:46.633]
    r'\[(?P<accept_date>.+)\]\s+'
    # Match both HTTP and TCP log formats
    r'('
    # frontend backend/server1
    # FIXME: extra () ?
    r'((?P<http_frontend_name>.*)\s+(?P<http_backend_name>.*)\/(?P<http_server_name>.*)\s+'
    # 0/51536/1/48082/99627
    r'(?P<http_Tq>-?\d+)/(?P<http_Tw>-?\d+)/(?P<http_Tc>-?\d+)/'
    r'(?P<http_Tr>-?\d+)/(?P<http_Ta>\+?\d+)\s+'
    # 200 83285 - HTTP log format for status code and bytes read
    r'(?P<http_status_code>-?\d+)\s+(?P<http_bytes_read>\+?\d+)'
    r')|('
    # frontend backend/server1
    r'(?P<tcp_frontend_name>.*)\s+(?P<tcp_backend_name>.*)/(?P<tcp_server_name>.*)\s+'
    # 0/51536/1
    r'(?P<tcp_Tw>-?\d+)/(?P<tcp_Tc>-?\d+)/(?P<tcp_Tt>\+?\d+)\s+'
    # 259
    r'(?P<tcp_bytes_read>\+?\d+))'
    r')'
    # - - ---- (http) and -- (tcp)
    r'.*\s+'
    r'(?P<actconn>\d+)\/(?P<feconn>\d+)\/(?P<beconn>\d+)\/(?P<srv_conn>\d+)\/(?P<retries>\+?\d+)'
    # srv_queue/backend_queue
    r'(\s+(?P<srv_queue>\d+)\/(?P<backend_queue>\d+))'
    r'(\s+'
    # # optional HTTP-only |-delimited list of request and response headers (probably not correct)
    r'({(?P<captured_request_headers>.*)}\s+{(?P<captured_response_headers>.*)}\s+|{(?P<headers>.*)}\s+|\s+)?'
    # match the entire string until the (optional) closing double-quote to account for truncated
    # log lines (e.g. lines sent to remote syslog server may be truncated to ~1024 characters).
    r'"(?P<http_request>[^\"]+)"?'
    r')?'
    r'\Z'  # end of line
)

HTTP_REQUEST_REGEX = re.compile(
    r'(?P<method>\w+)\s+'
    r'(?P<path>(/[`´\\<>/\w:,;.#$!?=&@%_+\'*^~|()\[\]{\}-]*)+)'
    r'(\s+(?P<protocol>\w+/\d\.\d))?'
)


class LineType(enum.Enum):
    HTTP = 0
    TCP = 1


class Line(object):
    """For a precise and more detailed description of every field see:
    http://cbonte.github.io/haproxy-dconv/2.2/configuration.html#8.2.3
    """
    log_type = None

    #: IP of the upstream server that made the connection to HAProxy.
    client_ip = None
    #: Port used by the upstream server that made the connection to HAProxy.
    client_port = None

    # raw string from log line and its python datetime version
    raw_accept_date = None
    #: datetime object with the exact date when the connection to HAProxy was
    #: made. It's called access_date/request_date depending on the log type.
    accept_date = request_date = None

    #: HAProxy frontend that received the connection.
    frontend_name = None
    #: HAProxy backend that the connection was sent to.
    backend_name = None
    #: Downstream server that HAProxy send the connection to.
    server_name = None

    #: Time in milliseconds waiting the client to send the full HTTP request
    #: (``Tq`` in HAProxy documentation).
    time_wait_request = None
    #: Time in milliseconds that the request spend on HAProxy queues
    #: (``Tw`` in HAProxy documentation).
    time_wait_queues = None
    #: Time in milliseconds to connect to the final server
    #: (``Tc`` in HAProxy documentation).
    time_connect_server = None
    #: Time in milliseconds waiting the downstream server to send the full
    #: HTTP response (``Tr`` in HAProxy documentation).
    time_wait_response = None
    #: Total time in milliseconds between accepting the HTTP request and
    #: sending back the HTTP response (``Tt`` or ``Ta`` in HAProxy
    #: documentation depending on the log type).
    total_time = None

    #: HTTP status code returned to the client.
    status_code = None
    #: Total number of bytes send back to the client.
    bytes_read = None

    # not used by now
    captured_request_cookie = None
    captured_response_cookie = None

    # not used by now
    termination_state = None

    #: Total number of concurrent connections on the process when the
    #: session was logged (``actconn`` in HAProxy documentation).
    connections_active = None
    #: Total number of concurrent connections on the frontend when the
    #: session was logged (``feconn`` in HAProxy documentation).
    connections_frontend = None
    #: Total number of concurrent connections handled by the backend when
    #: the session was logged (``beconn`` in HAProxy documentation).
    connections_backend = None
    #: Total number of concurrent connections still active on the server
    #: when the session was logged (``srv_conn`` in HAProxy documentation).
    connections_server = None
    #: Number of connection retries experienced by this session when
    # trying to connect to the server.
    retries = None

    #: Total number of requests which were processed before this one in
    #: the server queue (``srv_queue`` in HAProxy documentation).
    queue_server = None
    #: Total number of requests which were processed before this one in
    #: the backend's global queue (``backend_queue`` in HAProxy documentation).
    queue_backend = None

    # List of headers captured in the request.
    captured_request_headers = None
    # List of headers captured in the response.
    captured_response_headers = None

    raw_http_request = None
    #: HTTP method (GET, POST...) used on this request.
    http_request_method = None
    #: Requested HTTP path.
    http_request_path = None
    #: HTTP version used on this request.
    http_request_protocol = None

    raw_line = None

    def __init__(self, line):
        self.raw_line = line

        self.is_valid = self._parse_line(line)

    @property
    def is_https(self):
        """Returns True if the log line is a SSL connection. False otherwise.
        """
        if ':443' in self.http_request_path:
            return True
        return False

    def is_within_time_frame(self, start, end):
        if not start:
            return True
        elif start > self.accept_date:
            return False

        if not end:
            return True
        elif end < self.accept_date:
            return False

        return True

    @property
    def ip(self):
        """Returns the IP provided on the log line, or the client_ip if absent/empty."""
        if self.captured_request_headers is not None:
            ip = self.captured_request_headers.split('|')[0]
            if ip:
                return ip
        return self.client_ip

    def _parse_http_fields(self, matches):
        self.frontend_name = matches.group('http_frontend_name')
        self.backend_name = matches.group('http_backend_name')
        self.server_name = matches.group('http_server_name')

        self.time_wait_request = int(matches.group('http_Tq'))
        self.time_wait_queues = int(matches.group('http_Tw'))
        self.time_connect_server = int(matches.group('http_Tc'))
        self.time_wait_response = int(matches.group('http_Tr'))
        self.total_time = matches.group('http_Ta')

        self.status_code = matches.group('http_status_code')
        self.bytes_read = matches.group('http_bytes_read')

        self.captured_request_headers = matches.group('captured_request_headers')
        self.captured_response_headers = matches.group('captured_response_headers')
        if matches.group('headers') is not None:
            self.captured_request_headers = matches.group('headers')

        self.raw_http_request = matches.group('http_request')
        if self.raw_http_request is not None:
            self._parse_http_request()

    def _parse_tcp_fields(self, matches):
        self.frontend_name = matches.group('tcp_frontend_name')
        self.backend_name = matches.group('tcp_backend_name')
        self.server_name = matches.group('tcp_server_name')

        self.time_wait_queues = int(matches.group('tcp_Tw'))
        self.time_connect_server = int(matches.group('tcp_Tc'))
        self.total_time = int(matches.group('tcp_Tt'))

        self.bytes_read = matches.group('tcp_bytes_read')

    def _parse_protocol_specific_fields(self, matches):
        if matches.group("http_frontend_name") is not None:
            self.log_type = LineType.HTTP
            self._parse_http_fields(matches)
        else:
            self.log_type = LineType.TCP
            self._parse_tcp_fields(matches)

        self.connections_active = matches.group('actconn')
        self.connections_frontend = matches.group('feconn')
        self.connections_backend = matches.group('beconn')
        self.connections_server = matches.group('srv_conn')
        self.retries = matches.group('retries')

        self.queue_server = int(matches.group('srv_queue'))
        self.queue_backend = int(matches.group('backend_queue'))

    def _parse_line(self, line):
        matches = HAPROXY_LINE_REGEX.match(line)
        if matches is None:
            return False

        self.client_ip = matches.group('client_ip')
        self.client_port = int(matches.group('client_port'))

        self.raw_accept_date = matches.group('accept_date')
        self.accept_date = self._parse_accept_date()
        self.request_date = self.accept_date

        self._parse_protocol_specific_fields(matches)
        return True

    def _parse_accept_date(self):
        return datetime.strptime(self.raw_accept_date, '%d/%b/%Y:%H:%M:%S.%f')

    def _parse_http_request(self):
        matches = HTTP_REQUEST_REGEX.match(self.raw_http_request)
        if matches:
            self.http_request_method = matches.group('method')
            self.http_request_path = matches.group('path')
            self.http_request_protocol = matches.group('protocol')
        else:
            self.handle_bad_http_request()

    def handle_bad_http_request(self):
        self.http_request_method = 'invalid'
        self.http_request_path = 'invalid'
        self.http_request_protocol = 'invalid'

        if self.raw_http_request != '<BADREQ>':
            print(f'Could not process HTTP request {self.raw_http_request}')


# it is not coverage covered as this is executed by the multiprocessor module,
# and setting it up on coverage just for two lines is not worth it
def parse_line(line):  # pragma: no cover
    return Line(line.strip())
