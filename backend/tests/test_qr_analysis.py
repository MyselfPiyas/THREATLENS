import cv2
import numpy as np
import pytest

from app.services.qr_analysis import decode_qr


def qr_png(value: str) -> bytes:
    image = cv2.QRCodeEncoder_create().encode(value)
    image = cv2.copyMakeBorder(image, 4, 4, 4, 4, cv2.BORDER_CONSTANT, value=255)
    image = cv2.resize(image, None, fx=12, fy=12, interpolation=cv2.INTER_NEAREST)
    ok, encoded = cv2.imencode(".png", image)
    assert ok
    return encoded.tobytes()


def test_decode_url_qr() -> None:
    assert decode_qr(qr_png("https://example.com/login")) == "https://example.com/login"


def test_decode_plain_text_qr() -> None:
    assert decode_qr(qr_png("hello from a QR code")) == "hello from a QR code"


def test_decode_inverted_payment_style_qr() -> None:
    image = qr_png("upi://pay?pa=test@example")
    source = cv2.imdecode(np.frombuffer(image, dtype=np.uint8), cv2.IMREAD_GRAYSCALE)
    inverted = cv2.bitwise_not(source)
    ok, encoded = cv2.imencode(".png", inverted)
    assert ok
    assert decode_qr(encoded.tobytes()) == "upi://pay?pa=test@example"


def test_invalid_image_fails_safely() -> None:
    with pytest.raises(ValueError, match="readable image|No QR code"):
        decode_qr(b"not an image")


def test_oversized_image_rejected_before_decode() -> None:
    with pytest.raises(ValueError, match="5 MB"):
        decode_qr(b"0" * (5 * 1024 * 1024 + 1))
