from __future__ import annotations

from io import BytesIO


def decode_qr(data: bytes) -> str:
    if len(data) > 5 * 1024 * 1024:
        raise ValueError("QR image exceeds the 5 MB limit.")
    try:
        import cv2  # type: ignore
        import numpy as np  # type: ignore
    except ImportError as error:
        raise RuntimeError("QR decoding is unavailable because the decoder dependency is not installed.") from error
    image = cv2.imdecode(np.frombuffer(data, dtype=np.uint8), cv2.IMREAD_COLOR)
    if image is None:
        raise ValueError("The uploaded file is not a readable image.")
    decoder = cv2.QRCodeDetector()
    # Payment QR artwork commonly uses white modules on a dark canvas. OpenCV
    # primarily expects the inverse, so try both the original and a luminance
    # inversion without altering the uploaded file or following its content.
    candidates = [image]
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    candidates.extend([cv2.bitwise_not(image), cv2.bitwise_not(gray), gray])
    value = ""
    for candidate in candidates:
        value, _, _ = decoder.detectAndDecode(candidate)
        if value:
            break
        if hasattr(decoder, "detectAndDecodeMulti"):
            found, values, _, _ = decoder.detectAndDecodeMulti(candidate)
            if found and values:
                value = "\n".join(item for item in values if item)
                if value:
                    break
    if not value:
        raise ValueError("No QR code could be decoded from this image.")
    return value[:8192]
