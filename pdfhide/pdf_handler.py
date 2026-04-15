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
# pdf_handler.py
__version__ = "0.1"
#
# PDF embedding/extraction support for pdf_hide v0.1
#
# Adds the ability to hide binary PDF files inside other PDF files using
# the existing pdf_hide steganographic algorithm.
#
# Strategy:
#   Mirrors the design of image_handler.py.  The hidden PDF bytes are wrapped
#   in a lightweight envelope before being passed to PDF_stego.embed(), so
#   that the extractor can reliably distinguish a hidden PDF payload from a
#   plain-text message.
#
#   ENVELOPE FORMAT (all multi-byte integers are big-endian):
#   ┌─────────────────────────────────────────────────────┐
#   │  4 bytes  │  magic number: b"PHPD"                  │
#   │  1 byte   │  version: 0x01                          │
#   │  4 bytes  │  original PDF size (uint32)             │
#   │  4 bytes  │  compressed payload size (uint32)       │
#   │  N bytes  │  zlib-compressed PDF bytes              │
#   └─────────────────────────────────────────────────────┘
#
#   On extraction the caller checks for the magic number with is_pdf_envelope()
#   to decide whether the output is a plain-text message, an image envelope
#   (PHIM), or a nested PDF envelope (PHPD), and then calls unwrap() to
#   recover the original PDF bytes.
#
#   Usage example
#   -------------
#   Embedding:
#       from pdfhide import pdf_handler
#       envelope = pdf_handler.wrap(open("secret.pdf","rb").read())
#       stego.embed(envelope, key)          # envelope is bytes, same as image
#
#   Extracting:
#       raw = open(output_path, "rb").read()
#       if pdf_handler.is_pdf_envelope(raw):
#           pdf_bytes = pdf_handler.unwrap(raw)
#           open("recovered.pdf","wb").write(pdf_bytes)
#

MAGIC = b"PHPD"
VERSION = b"\x01"


# ─────────────────────────────────────────────
#  PUBLIC API
# ─────────────────────────────────────────────

def wrap(pdf_bytes):
    """
    Wraps raw PDF bytes in a pdf_hide PDF envelope.

    Parameters
    ----------
    pdf_bytes : bytes
        Raw bytes of the PDF file to hide.

    Returns
    -------
    bytes
        The envelope payload ready to be passed to PDF_stego.embed().

    Raises
    ------
    ValueError
        If pdf_bytes is empty or does not start with the PDF magic ``%PDF``.
    """
    if not pdf_bytes:
        raise ValueError("pdf_bytes must not be empty")
    if not pdf_bytes.startswith(b"%PDF"):
        raise ValueError(
            "pdf_bytes does not appear to be a valid PDF file "
            "(missing %PDF header)"
        )

    # Compress the PDF data
    compressed = zlib.compress(pdf_bytes, level=zlib.Z_BEST_COMPRESSION)

    # Build header
    orig_size_bytes = len(pdf_bytes).to_bytes(4, "big")
    comp_size_bytes = len(compressed).to_bytes(4, "big")

    envelope = (
        MAGIC
        + VERSION
        + orig_size_bytes
        + comp_size_bytes
        + compressed
    )
    return envelope


def unwrap(payload):
    """
    Recovers a PDF from a pdf_hide PDF envelope.

    Parameters
    ----------
    payload : bytes
        Raw bytes as written to the output file by PDF_stego.extract().

    Returns
    -------
    bytes
        The original PDF bytes.

    Raises
    ------
    ValueError
        If the payload is not a valid pdf_hide PDF envelope.
    """
    if not is_pdf_envelope(payload):
        raise ValueError("Payload does not contain a pdf_hide PDF envelope")

    offset = 4  # skip magic
    version = payload[offset:offset + 1]
    offset += 1

    if version != VERSION:
        raise ValueError(f"Unsupported envelope version: {version!r}")

    orig_size = int.from_bytes(payload[offset:offset + 4], "big")
    offset += 4
    comp_size = int.from_bytes(payload[offset:offset + 4], "big")
    offset += 4

    compressed = payload[offset:offset + comp_size]
    if len(compressed) != comp_size:
        raise ValueError("Envelope is truncated: compressed data is incomplete")

    pdf_bytes = zlib.decompress(compressed)

    if len(pdf_bytes) != orig_size:
        raise ValueError(
            f"Size mismatch after decompression: "
            f"expected {orig_size} bytes, got {len(pdf_bytes)}"
        )

    return pdf_bytes


def is_pdf_envelope(payload):
    """
    Returns True if *payload* starts with the pdf_hide PDF magic number.

    Use this alongside ``image_handler.is_image_envelope()`` to dispatch
    extracted payloads to the right handler:

        if pdf_handler.is_pdf_envelope(raw):
            pdf_bytes = pdf_handler.unwrap(raw)
        elif image_handler.is_image_envelope(raw):
            img_bytes, ext = image_handler.unwrap(raw)
        else:
            text = raw.decode("utf-8")

    Parameters
    ----------
    payload : bytes

    Returns
    -------
    bool
    """
    return isinstance(payload, (bytes, bytearray)) and payload[:4] == MAGIC


def estimate_capacity_needed(pdf_path):
    """
    Estimates the number of bytes that will need to be embedded for a given
    PDF file, accounting for zlib compression.  Useful for sanity-checking
    whether the cover PDF has enough TJ operators before attempting to embed.

    Parameters
    ----------
    pdf_path : str

    Returns
    -------
    int  approximate number of bytes to embed
    """
    with open(pdf_path, "rb") as f:
        raw = f.read()
    envelope = wrap(raw)
    return len(envelope)
