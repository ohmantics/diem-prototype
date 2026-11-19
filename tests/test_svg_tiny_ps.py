"""The SVG Tiny PS check that decides whether a mark may be shown.   # draft: #marks"""

import pytest

from diem import svg_tiny_ps
from examples import hospital_world

HEAD = b'<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 10 10">'


def test_the_example_marks_conform():
    assert svg_tiny_ps.problems(hospital_world.MARK_IMAGE) == []
    assert svg_tiny_ps.problems(hospital_world.OTHER_IMAGE) == []


@pytest.mark.parametrize(
    "image, expected",
    [
        (
            HEAD + b"<title>t</title><script>alert(1)</script></svg>",
            "<script> is not allowed inside <svg>",
        ),
        (
            HEAD
            + b'<title>t</title><path x="0" y="0" width="1" height="1" onclick="f()"/></svg>',
            "attribute onclick is not allowed on <path>",
        ),
        (
            HEAD
            + b'<title>t</title><path x="0" y="0" width="1" height="1" fill="url(http://x.example/a)"/></svg>',
            "<path> refers outside the document (http://x.example/a)",
        ),
        (
            HEAD + b'<title>t</title><use href="http://x.example/a"/></svg>',
            "<use> refers outside the document",
        ),
        (HEAD + b"</svg>", "<svg> needs exactly one <title>"),
        (
            HEAD + b"<title>a</title><title>b</title></svg>",
            "<svg> needs exactly one <title>",
        ),
        (
            b'<?xml version="1.0"?><!DOCTYPE svg><svg xmlns="http://www.w3.org/2000/svg"/>',
            "it declares a document type or an entity",
        ),
        (b"<svg", "it is not well-formed XML"),
        (
            b'<html xmlns="http://www.w3.org/1999/xhtml"/>',
            "its root is not an SVG svg element",
        ),
        (b"x" * 40000, "it is larger than"),
    ],
)
def test_what_is_not_svg_tiny_ps_is_reported(image, expected):
    assert any(expected in problem for problem in svg_tiny_ps.problems(image))


def test_a_version_other_than_1_2_is_reported():
    image = hospital_world.MARK_IMAGE.replace(b'version="1.2"', b'version="1.1"')
    assert any('version="1.1"' in problem for problem in svg_tiny_ps.problems(image))
