# -*- coding: utf-8 -*-
from copy import deepcopy
from haproxy.line import Line
from haproxy.line import LineType

import pytest


DEFAULT_DATA = {
    'syslog_date': 'Dec  9 13:01:26',
    'process_name_and_pid': 'localhost haproxy[28029]:',
    'client_ip': '127.0.0.1',
    'client_port': 2345,
    'accept_date': '09/Dec/2013:12:59:46.633',
    'http_frontend_name': 'loadbalancer',
    'http_backend_name': 'default',
    'http_server_name': 'instance8',
    'tcp_frontend_name': 'loadbalancer',
    'tcp_backend_name': 'default',
    'tcp_server_name': 'instance8',
    'Tq': 0,
    'Tw': 51536,
    'Tc': 1,
    'Tr': 48082,
    'Ta': '99627',
    'Tt': '302045',
    'http_status_code': '200',
    'http_bytes_read': '83285',
    'tcp_bytes_read': '18923',
    'actconn': '87',
    'feconn': '89',
    'beconn': '98',
    'srv_conn': '1',
    'retries': '20',
    'srv_queue': 2,
    'backend_queue': 67,
    'headers': ' {77.24.148.74}',
    'http_request': 'GET /path/to/image HTTP/1.1',
}


class LinesGenerator:
    def __init__(self, line_type=LineType.HTTP, line_format=None):
        self.data = deepcopy(DEFAULT_DATA)
        self.line_type = line_type
        self.line_format = line_format

    def __call__(self, *args, **kwargs):
        self.data.update(**kwargs)
        self.data['client_ip_and_port'] = '{client_ip}:{client_port}'.format(
            **self.data
        )
        self.data[
            'http_server_names'
        ] = '{http_frontend_name} {http_backend_name}/{http_server_name}'.format(**self.data)
        self.data[
            'tcp_server_names'
        ] = '{tcp_frontend_name} {tcp_backend_name}/{tcp_server_name}'.format(**self.data)
        self.data['http_timers'] = '{Tq}/{Tw}/{Tc}/{Tr}/{Ta}'.format(**self.data)
        self.data['tcp_timers'] = '{Tw}/{Tc}/{Tt}'.format(**self.data)
        self.data['http_status_and_bytes'] = '{http_status_code} {http_bytes_read}'.format(**self.data)
        self.data['tcp_bytes_read'] = self.data['tcp_bytes_read']
        self.data['connections_and_retries'] = '{actconn}/{feconn}/{beconn}/{srv_conn}/{retries}'.format(
            **self.data
        )
        self.data['queues'] = '{srv_queue}/{backend_queue}'.format(**self.data)

        log_line = self.line_format.format(**self.data)
        return Line(log_line)


@pytest.fixture
def default_line_data():
    return DEFAULT_DATA


@pytest.fixture
def http_line_factory():
    # queues and headers parameters are together because if no headers are
    # saved the field is completely empty and thus there is no double space
    # between queue backend and http request.
    raw_line = (
        '{syslog_date} {process_name_and_pid} {client_ip_and_port} '
        '[{accept_date}] {http_server_names} {http_timers} {http_status_and_bytes} '
        '- - ---- {connections_and_retries} {queues}{headers} '
        '"{http_request}"'
    )
    generator = LinesGenerator(line_format=raw_line)
    return generator


@pytest.fixture
def tcp_line_factory():
    raw_line = (
        '{syslog_date} {process_name_and_pid} {client_ip_and_port} '
        '[{accept_date}] {tcp_server_names} {tcp_timers} {tcp_bytes_read} '
        '-- {connections_and_retries} {queues}'
    )
    generator = LinesGenerator(line_format=raw_line)
    return generator

@pytest.fixture
def plain_line_factory():
    # A variant of haproxy line without syslog and process data
    raw_line = (
        '{client_ip_and_port} '
        '[{accept_date}] {tcp_server_names} {tcp_timers} {tcp_bytes_read} '
        '-- {connections_and_retries} {queues}'
    )
    generator = LinesGenerator(line_format=raw_line)
    return generator