# -*- coding: utf-8 -*-
from datetime import datetime
from datetime import timedelta

import pytest


NOW = datetime.now()
TWO_DAYS_AGO = NOW - timedelta(days=2)
IN_TWO_DAYS = NOW + timedelta(days=2)


def test_default_http_values(http_line_factory, default_line_data):
    line = http_line_factory()

    assert line.client_ip == default_line_data['client_ip']
    assert line.client_port == default_line_data['client_port']

    assert line.raw_accept_date in default_line_data['accept_date']

    assert line.frontend_name == default_line_data['http_frontend_name']
    assert line.backend_name == default_line_data['http_backend_name']
    assert line.server_name == default_line_data['http_server_name']

    assert line.time_wait_request == default_line_data['Tq']
    assert line.time_wait_queues == default_line_data['Tw']
    assert line.time_connect_server == default_line_data['Tc']
    assert line.time_wait_response == default_line_data['Tr']
    assert line.total_time == default_line_data['Ta']

    assert line.status_code == default_line_data['http_status_code']
    assert line.bytes_read == default_line_data['http_bytes_read']

    assert line.connections_active == default_line_data['actconn']
    assert line.connections_frontend == default_line_data['feconn']
    assert line.connections_backend == default_line_data['beconn']
    assert line.connections_server == default_line_data['srv_conn']
    assert line.retries == default_line_data['retries']

    assert line.queue_server == default_line_data['srv_queue']
    assert line.queue_backend == default_line_data['backend_queue']

    assert line.captured_request_headers == default_line_data['headers'].strip()[1:-1]
    assert line.captured_response_headers is None

    assert line.raw_http_request == default_line_data['http_request']

    assert line.is_valid


def test_defaults_tcp_values(tcp_line_factory, default_line_data):
    line = tcp_line_factory()

    assert line.is_valid


def test_unused_values(http_line_factory):
    line = http_line_factory()
    assert line.captured_request_cookie is None
    assert line.captured_response_cookie is None
    assert line.termination_state is None


def test_datetime_value(http_line_factory):
    line = http_line_factory()
    assert isinstance(line.accept_date, datetime)


def test_http_request_values(http_line_factory):
    method = 'PUT'
    path = '/path/to/my/image'
    protocol = 'HTTP/2.0'
    line = http_line_factory(http_request=f'{method} {path} {protocol}')
    assert line.http_request_method == method
    assert line.http_request_path == path
    assert line.http_request_protocol == protocol


def test_invalid_line(http_line_factory):
    line = http_line_factory(http_bytes_read='wroooong')
    assert not line.is_valid


def test_no_captured_headers(http_line_factory):
    """A log line without captured headers is still valid."""
    line = http_line_factory(headers='')
    assert line.is_valid


def test_request_and_response_captured_headers(http_line_factory):
    """Request and response headers captured are parsed correctly."""
    request_headers = '{something}'
    response_headers = '{something_else}'
    line = http_line_factory(headers=f' {request_headers} {response_headers}')
    assert line.is_valid
    assert f'{{{line.captured_request_headers}}}' == request_headers
    assert f'{{{line.captured_response_headers}}}' == response_headers


def test_request_is_https_valid(http_line_factory):
    """Check that if a log line contains the SSL port on it, is reported
    as a https connection.
    """
    line = http_line_factory(http_request='GET /domain:443/to/image HTTP/1.1')
    assert line.is_https


def test_request_is_https_false(http_line_factory):
    """Check that if a log line does not contains the SSL port on it, is
    not reported as a https connection.
    """
    line = http_line_factory(http_request='GET /domain:80/to/image HTTP/1.1')
    assert not line.is_https


def test_request_is_front_page(http_line_factory):
    """Check that if a request is for the front page the request path is
    correctly stored.
    """
    line = http_line_factory(http_request='GET / HTTP/1.1')
    assert line.http_request_path == '/'


@pytest.mark.parametrize(
    'process',
    [
        'ip-192-168-1-1 haproxy[28029]:',
        'dvd-ctrl1 haproxy[403100]:',
        'localhost.localdomain haproxy[2345]:',
    ],
)
def test_process_names(http_line_factory, process):
    """Checks that different styles of process names are handled correctly."""
    line = http_line_factory(process_name_and_pid=process,)
    assert line.is_valid is True


def test_unparseable_http_request(http_line_factory):
    line = http_line_factory(http_request='something')
    assert line.http_request_method == 'invalid'
    assert line.http_request_path == 'invalid'
    assert line.http_request_protocol == 'invalid'


def test_truncated_requests(http_line_factory):
    """Check that truncated requests are still valid.

    That would be requests that do not have the protocol part specified.
    """
    line = http_line_factory(http_request='GET /')
    assert line.http_request_method == 'GET'
    assert line.http_request_path == '/'
    assert line.http_request_protocol is None


@pytest.mark.parametrize(
    'syslog',
    [
        # nixos format
        '2017-07-06T14:29:39+02:00',
        # regular format
        'Dec  9 13:01:26',
    ],
)
def test_syslog(http_line_factory, syslog):
    """Check that the timestamp at the beginning are parsed.

    We support different syslog formats, NixOS style and the one on other Linux.
    """
    line = http_line_factory(syslog_date=syslog)
    assert line.is_valid is True


def test_ip_from_headers(http_line_factory):
    """Check that the IP from the captured headers takes precedence."""
    line = http_line_factory(headers=' {1.2.3.4}')
    assert line.ip == '1.2.3.4'


@pytest.mark.parametrize(
    'ip',
    ['127.1.2.7', '1.127.230.47', 'fe80::9379:c29e:6701:cef8', 'fe80::9379:c29e::'],
)
def test_ip_from_client_ip(http_line_factory, ip):
    """Check that if there is no IP on the captured headers, the client IP is used."""
    line = http_line_factory(headers='', client_ip=ip)
    assert line.ip == ip


@pytest.mark.parametrize(
    'start, end, result',
    [
        (None, None, True),
        (TWO_DAYS_AGO, None, True),
        (IN_TWO_DAYS, None, False),
        (TWO_DAYS_AGO, IN_TWO_DAYS, True),
        (TWO_DAYS_AGO, TWO_DAYS_AGO, False),
    ],
)
def test_is_within_timeframe(http_line_factory, start, end, result):
    """Check that a line is within a given time frame."""
    line = http_line_factory(accept_date=NOW.strftime('%d/%b/%Y:%H:%M:%S.%f'))
    assert line.is_within_time_frame(start, end) is result


def test_truncated_http_log_line(http_line_factory):
    http_line_factory.line_format = http_line_factory.line_format[:-1]
    method = "GET"
    path = "/truncated_pat"
    line = http_line_factory(http_request=f'{method} {path}')

    assert line.is_valid
    assert line.http_request_method == method
    assert line.http_request_path == path
    assert line.http_request_protocol is None
