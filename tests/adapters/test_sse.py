from cui_guard.adapters.sse import SSEDecoder, SSEEvent, encode_event


def test_decoder_handles_split_utf8_and_events():
    raw = "event: delta\ndata: café ok\n\n".encode()
    cut = raw.index("é".encode()) + 1  # mid-codepoint
    d = SSEDecoder()
    evs = d.feed(raw[:cut]) + d.feed(raw[cut:-1]) + d.feed(raw[-1:])
    assert evs == [SSEEvent("delta", "café ok")]
    assert d.close() == []


def test_line_endings_comments_multiline():
    d = SSEDecoder()
    evs = d.feed(b": hi\r\ndata: a\rdata: b\r\n\r\n")
    evs += d.feed(b"data: c\n\n")
    assert evs == [SSEEvent(None, "a\nb"), SSEEvent(None, "c")]


def test_cr_lf_split_across_chunks():
    d = SSEDecoder()
    evs = d.feed(b"data: x\r") + d.feed(b"\n\r") + d.feed(b"\n")
    assert evs == [SSEEvent(None, "x")]


def test_close_returns_unterminated_event():
    d = SSEDecoder()
    assert d.feed(b"event: e\ndata: tail") == []
    assert d.close() == [SSEEvent("e", "tail")]


def test_encode_round_trip():
    evs = [SSEEvent("message_start", "{}"), SSEEvent(None, "a\nb\n"), SSEEvent("x", "")]
    wire = b"".join(encode_event(e) for e in evs)
    assert wire.startswith(b"event: message_start\ndata: {}\n\n")
    d = SSEDecoder()
    assert d.feed(wire) + d.close() == evs
