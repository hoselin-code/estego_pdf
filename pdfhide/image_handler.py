#!/usr/bin/python3
import zlib
import os

#
#
#
# PDF HIDE
#

#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see [http://www.gnu.org/licenses/].
#
# Copyright (C) 2013 Nicolas Canceill
#

#
# image_handler.py
__version__ = "0.1"
#
# Image embedding/extraction support for pdf_hide v0.1
#
# Adds the ability to hide binary image files (PNG, JPEG, BMP, GIF, WEBP, etc.)
# inside PDF files using the existing pdf_hide steganographic algorithm.
#
# Strategy:
#   The existing algo embeds raw bytes. To distinguish an embedded image from
#   plain text, and to carry metadata needed for proper reconstruction, we
#   wrap the image bytes in a lightweight envelope before embedding:
#
#   ENVELOPE FORMAT (all multi-byte integers are big-endian):
#   ┌─────────────────────────────────────────────────────┐
#   │  4 bytes  │  magic number: b"PHIM"                  │
#   │  1 byte   │  version: 0x01                          │
#   │  3 bytes  │  extension length (uint24) + extension  │
#   │           │  (e.g. b"\x03png" → ext = "png")        │
#   │  4 bytes  │  original image size (uint32)           │
#   │  4 bytes  │  compressed payload size (uint32)       │
#   │  N bytes  │  zlib-compressed image bytes            │
#   └─────────────────────────────────────────────────────┘
#
#   On extraction the caller checks for the magic number to decide whether
#   the output is a plain-text message or an image envelope, and then calls
#   unwrap() to recover the original file.
#

MAGIC = b"PHIM"
VERSION = b"\x01"

# Supported image extensions (used only for validation / default naming)
SUPPORTED_EXTENSIONS = {
    "png", "jpg", "jpeg", "bmp", "gif", "webp", "tiff", "tif"
}

# ─────────────────────────────────────────────
#  PUBLIC API
# ─────────────────────────────────────────────

def wrap(image_bytes, extension):
    """
    Wraps raw image bytes in a pdf_hide image envelope.

    Parameters
    ----------
    image_bytes : bytes
        Raw bytes of the image file to hide.
    extension : str
        File extension without the leading dot (e.g. "png", "jpg").
        Used to restore the file with the correct name on extraction.

    Returns
    -------
    bytes
        The envelope payload ready to be passed to PDF_stego.embed().

    Raises
    ------
    ValueError
        If image_bytes is empty or extension is missing.
    """
    if not image_bytes:
        raise ValueError("image_bytes must not be empty")
    ext = extension.lower().lstrip(".")
    if not ext:
        raise ValueError("A file extension must be provided (e.g. 'png')")

    ext_bytes = ext.encode("ascii")
    if len(ext_bytes) > 0xFFFFFF:
        raise ValueError("Extension string is unreasonably long")

    # Compress the image data
    compressed = zlib.compress(image_bytes, level=zlib.Z_BEST_COMPRESSION)

    # Build header
    ext_len_bytes = len(ext_bytes).to_bytes(3, "big")
    orig_size_bytes = len(image_bytes).to_bytes(4, "big")
    comp_size_bytes = len(compressed).to_bytes(4, "big")

    envelope = (
        MAGIC
        + VERSION
        + ext_len_bytes
        + ext_bytes
        + orig_size_bytes
        + comp_size_bytes
        + compressed
    )
    return envelope


def unwrap(payload):
    """
    Recovers an image and its extension from a pdf_hide image envelope.

    Parameters
    ----------
    payload : bytes
        Raw bytes as written to the output file by PDF_stego.extract().

    Returns
    -------
    tuple (image_bytes: bytes, extension: str)
        The original image bytes and its extension (e.g. "png").

    Raises
    ------
    ValueError
        If the payload is not a valid pdf_hide image envelope.
    """
    if not is_image_envelope(payload):
        raise ValueError("Payload does not contain a pdf_hide image envelope")

    offset = 4  # skip magic
    version = payload[offset:offset + 1]
    offset += 1

    if version != VERSION:
        raise ValueError(f"Unsupported envelope version: {version!r}")

    ext_len = int.from_bytes(payload[offset:offset + 3], "big")
    offset += 3
    extension = payload[offset:offset + ext_len].decode("ascii")
    offset += ext_len

    orig_size = int.from_bytes(payload[offset:offset + 4], "big")
    offset += 4
    comp_size = int.from_bytes(payload[offset:offset + 4], "big")
    offset += 4

    compressed = payload[offset:offset + comp_size]
    if len(compressed) != comp_size:
        raise ValueError("Envelope is truncated: compressed data is incomplete")

    image_bytes = zlib.decompress(compressed)

    if len(image_bytes) != orig_size:
        raise ValueError(
            f"Size mismatch after decompression: "
            f"expected {orig_size} bytes, got {len(image_bytes)}"
        )

    return image_bytes, extension


def is_image_envelope(payload):
    """
    Returns True if *payload* starts with the pdf_hide image magic number.

    Use this to decide whether extracted data should be treated as an image
    or as plain text.

    Parameters
    ----------
    payload : bytes

    Returns
    -------
    bool
    """
    return isinstance(payload, (bytes, bytearray)) and payload[:4] == MAGIC


def get_extension_from_path(filepath):
    """
    Helper: extracts the lowercase extension from a file path.

    Parameters
    ----------
    filepath : str

    Returns
    -------
    str  (e.g. "png", "jpg")
    """
    _, ext = os.path.splitext(filepath)
    return ext.lstrip(".").lower()


def estimate_capacity_needed(image_path):
    """
    Estimates the number of bytes that will need to be embedded for a given
    image file, accounting for zlib compression.  Useful for sanity-checking
    whether the cover PDF has enough TJ operators before attempting to embed.

    Parameters
    ----------
    image_path : str

    Returns
    -------
    int  approximate number of bytes to embed
    """
    with open(image_path, "rb") as f:
        raw = f.read()
    ext = get_extension_from_path(image_path)
    envelope = wrap(raw, ext)
    return len(envelope)
