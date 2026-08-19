from exposure360_api.http_metadata import (
    SAFE_USER_AGENT,
    FixtureHttpTransport,
    HttpFixtureResponse,
    collect_fixture_http_metadata,
)


def test_head_metadata_is_bounded_and_does_not_persist_cookie_value() -> None:
    transport = FixtureHttpTransport(
        {
            ("HEAD", "https://www.example.com/"): HttpFixtureResponse(
                status_code=200,
                headers={
                    "Content-Type": "text/html",
                    "Server": "fixture",
                    "Set-Cookie": "secret=session-token",
                },
                body_chunks=(b"a" * 10, b"b" * 10),
            )
        }
    )

    result, metadata = collect_fixture_http_metadata(
        transport,
        start_url="https://www.example.com/",
        max_response_bytes=12,
        reauthorize_redirect=lambda _: True,
    )

    assert result == "SUCCESS"
    assert metadata["bytes_sampled"] == 12
    assert metadata["body_truncated"] is True
    assert metadata["headers"] == {
        "content-type": "text/html",
        "server": "fixture",
        "set_cookie_present": True,
    }
    assert transport.calls[0][2]["User-Agent"] == SAFE_USER_AGENT


def test_manual_redirect_is_reauthorized_before_second_transport_call() -> None:
    transport = FixtureHttpTransport(
        {
            ("HEAD", "https://www.example.com/"): HttpFixtureResponse(
                status_code=302,
                headers={"Location": "https://api.example.com/"},
            ),
            ("HEAD", "https://api.example.com/"): HttpFixtureResponse(
                status_code=204,
                headers={},
            ),
        }
    )

    result, metadata = collect_fixture_http_metadata(
        transport,
        start_url="https://www.example.com/",
        reauthorize_redirect=lambda url: url == "https://api.example.com/",
    )

    assert result == "SUCCESS"
    assert metadata["redirect_chain"] == ["https://api.example.com/"]
    assert [call[1] for call in transport.calls] == [
        "https://www.example.com/",
        "https://api.example.com/",
    ]


def test_get_is_only_a_bounded_fallback_when_head_is_not_supported() -> None:
    transport = FixtureHttpTransport(
        {
            ("HEAD", "https://www.example.com/"): HttpFixtureResponse(
                status_code=405,
                headers={},
            ),
            ("GET", "https://www.example.com/"): HttpFixtureResponse(
                status_code=200,
                headers={"Content-Type": "text/plain"},
                body_chunks=(b"fixture",),
            ),
        }
    )

    result, metadata = collect_fixture_http_metadata(
        transport,
        start_url="https://www.example.com/",
        max_response_bytes=16,
        reauthorize_redirect=lambda _: True,
    )

    assert result == "SUCCESS"
    assert metadata["status_code"] == 200
    assert [call[0] for call in transport.calls] == ["HEAD", "GET"]
    assert transport.calls[1][2]["Range"] == "bytes=0-15"


def test_denied_redirect_is_never_requested() -> None:
    transport = FixtureHttpTransport(
        {
            ("HEAD", "https://www.example.com/"): HttpFixtureResponse(
                status_code=302,
                headers={"Location": "https://outside.example.net/"},
            )
        }
    )

    result, _ = collect_fixture_http_metadata(
        transport,
        start_url="https://www.example.com/",
        reauthorize_redirect=lambda _: False,
    )

    assert result == "REDIRECT_DENIED"
    assert [call[1] for call in transport.calls] == ["https://www.example.com/"]


def test_redirect_loop_stops_at_configured_limit() -> None:
    transport = FixtureHttpTransport(
        {
            ("HEAD", "https://www.example.com/"): HttpFixtureResponse(
                status_code=302,
                headers={"Location": "/one"},
            ),
            ("HEAD", "https://www.example.com/one"): HttpFixtureResponse(
                status_code=302,
                headers={"Location": "/two"},
            ),
            ("HEAD", "https://www.example.com/two"): HttpFixtureResponse(
                status_code=302,
                headers={"Location": "/one"},
            ),
        }
    )

    result, metadata = collect_fixture_http_metadata(
        transport,
        start_url="https://www.example.com/",
        max_redirects=2,
        reauthorize_redirect=lambda _: True,
    )

    assert result == "TOO_MANY_REDIRECTS"
    assert metadata["redirect_chain"] == [
        "https://www.example.com/one",
        "https://www.example.com/two",
    ]
    assert [call[1] for call in transport.calls] == [
        "https://www.example.com/",
        "https://www.example.com/one",
        "https://www.example.com/two",
    ]


def test_invalid_scheme_credentials_and_timeout_are_bounded() -> None:
    transport = FixtureHttpTransport(
        {
            ("HEAD", "https://www.example.com/"): HttpFixtureResponse(
                status_code=200,
                headers={},
                timeout=True,
            )
        }
    )

    invalid, _ = collect_fixture_http_metadata(
        transport,
        start_url="file:///etc/passwd",
        reauthorize_redirect=lambda _: True,
    )
    credentials, _ = collect_fixture_http_metadata(
        transport,
        start_url="https://user:password@www.example.com/",
        reauthorize_redirect=lambda _: True,
    )
    timeout, _ = collect_fixture_http_metadata(
        transport,
        start_url="https://www.example.com/",
        reauthorize_redirect=lambda _: True,
    )

    assert invalid == "DENIED"
    assert credentials == "DENIED"
    assert timeout == "TIMEOUT"
