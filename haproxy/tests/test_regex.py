# -*- coding: utf-8 -*-
from datetime import datetime
from haproxy.line import HAPROXY_LINE_REGEX
from haproxy.line import HTTP_REQUEST_REGEX
from haproxy.line import LineType

import pytest
import random


def test_default_values(http_line_factory, default_line_data):
    """Check that the default line with default values is parsed."""
    line = http_line_factory()
    matches = HAPROXY_LINE_REGEX.match(line.raw_line)
    assert matches.group('http_request') == default_line_data['http_request']


def test_client_ip_and_port(http_line_factory):
    """Check that the client IP and port are extracted correctly."""
    ip = '192.168.0.250'
    port = '34'
    line = http_line_factory(client_ip=ip, client_port=port)
    matches = HAPROXY_LINE_REGEX.match(line.raw_line)

    assert matches.group('client_ip') == ip
    assert matches.group('client_port') == port


def test_accept_date(http_line_factory):
    """Check that the accept date is extracted correctly."""
    accept_date = datetime.now().strftime('%d/%b/%Y:%H:%M:%S.%f')
    line = http_line_factory(accept_date=accept_date)
    matches = HAPROXY_LINE_REGEX.match(line.raw_line)

    assert matches.group('accept_date') == accept_date


def _test_server_names(factory, factory_kwargs):
    line = factory(**factory_kwargs)
    matches = HAPROXY_LINE_REGEX.match(line.raw_line)

    for key, value in factory_kwargs.items():
        assert matches.group(key) == value


def test_http_server_names(http_line_factory):
    """Check that the server names are extracted correctly."""
    kwargs = {
        'http_frontend_name': 'SomeThing4',
        'http_backend_name':  'Another1',
        'http_server_name': 'Cloud9',
    }
    _test_server_names(http_line_factory, kwargs)


def test_tcp_server_names(tcp_line_factory):
    kwargs = {
        'tcp_frontend_name': 'SomeThing4',
        'tcp_backend_name':  'Another1',
        'tcp_server_name': 'Cloud9',
    }
    _test_server_names(tcp_line_factory, kwargs)


@pytest.mark.parametrize(
    'Tq,Tw,Tc,Tr,Ta',
    [
        ('0', '0', '0', '0', '0'),
        ('23', '55', '3', '4', '5'),
        ('-23', '-33', '-3', '-4', '5'),
        ('23', '33', '3', '4', '+5'),
    ],
)
def test_http_timers(http_line_factory, Tq, Tw, Tc, Tr, Ta):
    """Check that the HTTP timers are extracted correctly.

    Note that all timers can be negative but `Ta`,
    and that `tt` is the only one that can have a positive sign.
    """
    line = http_line_factory(LineType.HTTP, Tq=Tq, Tw=Tw, Tc=Tc, Tr=Tr, Ta=Ta)
    matches = HAPROXY_LINE_REGEX.match(line.raw_line)

    assert matches.group('http_Tq') == Tq
    assert matches.group('http_Tw') == Tw
    assert matches.group('http_Tc') == Tc
    assert matches.group('http_Tr') == Tr
    assert matches.group('http_Ta') == Ta


@pytest.mark.parametrize(
    'Tw,Tc,Tt',
    [
        ('0', '0', '0'),
        ('23', '55', '3',),
        ('-23', '-33', '5'),
        ('23', '33', '+5'),
    ],
)
def test_tcp_timers(tcp_line_factory, Tw, Tc, Tt):
    """Check that the TCP timers are extracted correctly.

    Note that all timers can be negative but `Ta`,
    and that `tt` is the only one that can have a positive sign.
    """
    line = tcp_line_factory(LineType.TCP, Tw=Tw, Tc=Tc, Tt=Tt)
    matches = HAPROXY_LINE_REGEX.match(line.raw_line)
    assert matches.group('tcp_Tw') == Tw
    assert matches.group('tcp_Tc') == Tc
    assert matches.group('tcp_Tt') == Tt


@pytest.mark.parametrize(
    'http_status_code, http_bytes_read', [('200', '0'), ('-301', '543'), ('200', '+543'),]
)
def test_status_and_bytes(http_line_factory, http_status_code, http_bytes_read):
    """Check that the status code and bytes are extracted correctly.

    Note that `status` can be negative (for terminated requests),
    and `bytes` can be prefixed with a plus sign.
    """
    line = http_line_factory(http_status_code=http_status_code, http_bytes_read=http_bytes_read)
    matches = HAPROXY_LINE_REGEX.match(line.raw_line)

    assert matches.group('http_status_code') == http_status_code
    assert matches.group('http_bytes_read') == http_bytes_read


@pytest.mark.parametrize(
    'actconn,feconn,beconn,srv_conn,retries',
    [
        ('0', '0', '0', '0', '0'),
        ('40', '10', '11', '12', '14'),
        ('40', '10', '11', '12', '+14'),
    ],
)
def test_connections_and_retries(http_line_factory, actconn, feconn, beconn, srv_conn, retries):
    """Check that the connections and retries are extracted correctly.

    Note that `retries` might have a plus sign prefixed.
    """
    line = http_line_factory(actconn=actconn, feconn=feconn, beconn=beconn,
                             srv_conn=srv_conn, retries=retries)
    matches = HAPROXY_LINE_REGEX.match(line.raw_line)

    assert matches.group('actconn') == actconn
    assert matches.group('feconn') == feconn
    assert matches.group('beconn') == beconn
    assert matches.group('srv_conn') == srv_conn
    assert matches.group('retries') == retries


@pytest.mark.parametrize('server, backend', [('0', '0'), ('200', '200'),])
def test_queues(http_line_factory, server, backend):
    """Check that the server and backend queues are extracted correctly."""
    line = http_line_factory(srv_queue=server, backend_queue=backend)
    matches = HAPROXY_LINE_REGEX.match(line.raw_line)

    assert matches.group('srv_queue') == server
    assert matches.group('backend_queue') == backend


@pytest.mark.parametrize(
    'request_header, response_header',
    [
        ('', ''),
        ('something', None),
        ('something here', 'and there'),
        ('multiple | request | headers', 'and | multiple | response ones'),
    ],
)
def test_captured_headers(http_line_factory, request_header, response_header):
    """Check that captured headers are extracted correctly."""
    if response_header:
        headers = f' {{{request_header}}} {{{response_header}}}'
    else:
        headers = f' {{{request_header}}}'
    line = http_line_factory(headers=headers)
    matches = HAPROXY_LINE_REGEX.match(line.raw_line)

    if response_header:
        assert matches.group('captured_request_headers') == request_header
        assert matches.group('captured_response_headers') == response_header
    else:
        assert matches.group('headers') == request_header
        assert matches.group('captured_request_headers') is None
        assert matches.group('captured_response_headers') is None


def test_http_request(http_line_factory):
    """Check that the HTTP request is extracted correctly."""
    http_request = 'something in the air'
    line = http_line_factory(http_request=http_request)
    matches = HAPROXY_LINE_REGEX.match(line.raw_line)

    assert matches.group('http_request') == http_request


@pytest.mark.parametrize(
    'path',
    [
        '/path/to/image',
        '/path/with/port:80',  # with port
        '/path/with/example.com',  # with domain
        '/path/to/article#section',  # with anchor
        '/article?hello=world&goodbye=lennin',  # with parameters
        '/article-with-dashes_and_underscores',  # dashes and underscores
        '/redirect_to?http://example.com',  # double slashes
        '/@@funny',  # at sign
        '/something%20encoded',  # percent sign
        '/++adding++is+always+fun',  # plus sign
        '/here_or|here',  # vertical bar
        '/here~~~e',  # tilde sign
        '/here_*or',  # asterisk sign
        '/something;or-not',  # colon
        '/something-important!probably',  # exclamation mark
        '/something$important',  # dollar sign
        "/there's-one's-way-or-another's"  # single quote sign
        '/there?la=as,is',  # comma
        '/here_or(here)',  # parenthesis
        '/here_or[here]',  # square brackets
        '/georg}von{grote/\\',  # curly brackets
        '/here_or<',  # less than
        '/here_or>',  # more than
        '/georg-von-grote/\\',  # back slash
        '/georg`von´grote/\\',  # diacritics
        '/georg`von^grote/\\',  # caret
    ],
)
def test_http_request_regex(path):
    """Test that the method/path/protocol are extracted properly from the HTTP request."""
    verbs = ('GET', 'POST', 'DELETE', 'PATCH', 'PUT')
    protocols = (
        'HTTP/1.0',
        'HTTP/1.1',
        'HTTP/2.0',
    )
    method = random.choice(verbs)
    protocol = random.choice(protocols)
    matches = HTTP_REQUEST_REGEX.match(f'{method} {path} {protocol}')
    assert matches.group('method') == method
    assert matches.group('path') == path
    assert matches.group('protocol') == protocol
