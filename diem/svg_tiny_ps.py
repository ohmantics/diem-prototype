"""Is an image an SVG Tiny PS drawing?   # draft: #marks

A visual mark is shown only if it is in a restricted image format that
excludes scripts, external references and animation. The format is SVG Tiny
Portable/Secure, defined by a RELAX NG schema in draft-svg-tiny-ps-abrotman
(section 7). profiles/svg-tiny-ps.json holds what that schema says about each
element it defines: its attributes (with the closed set of values where the
schema has one), the attributes it requires, and the elements it may contain.
The schema is closed: anything it does not list is a problem.

The schema also says the attributes `id` and `xml:id` appear on every
element; neither is enforced here. Attribute values the schema leaves
open are not checked, except that references must point into the same
document.
"""

import json
import re
from xml.etree import ElementTree

from diem.registry import PROFILES_DIR

SVG = "http://www.w3.org/2000/svg"
XML = "http://www.w3.org/XML/1998/namespace"
# draft-svg-tiny-ps-abrotman-13, section 2.4: SHOULD NOT exceed 32 kilobytes, uncompressed
MAX_OCTETS = 32 * 1024
SCHEMA = json.loads((PROFILES_DIR / "svg-tiny-ps.json").read_text())


def problems(image):
    """What is wrong with an image as SVG Tiny PS, as sentences; none if it conforms."""
    if len(image) > MAX_OCTETS:
        return [f"it is larger than {MAX_OCTETS} octets"]
    lowered = image.lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        return ["it declares a document type or an entity"]
    try:
        root = ElementTree.fromstring(image)
    except ElementTree.ParseError as error:
        return [f"it is not well-formed XML ({error})"]
    if root.tag != f"{{{SVG}}}svg":
        return ["its root is not an SVG svg element"]
    return _element(root)


def _local_name(tag):
    namespace, _, name = tag.rpartition("}")
    return name if namespace == f"{{{SVG}" else None


def _element(element):
    name = _local_name(element.tag) if isinstance(element.tag, str) else None
    rules = SCHEMA.get(name)
    if rules is None:
        return [f"{element.tag} is not an element of SVG Tiny PS"]
    found = _attributes(name, element, rules)
    allowed = rules["children"] + (["title"] if rules["title"] else [])
    text_only = "#text" in rules["children"]
    if text_only and len(element):
        found.append(f"<{name}> may contain text only")
    if not text_only and element.text and element.text.strip():
        found.append(f"<{name}> may not contain text")
    for child in element:
        child_name = _local_name(child.tag) if isinstance(child.tag, str) else None
        if child_name in allowed:
            found += _element(child)
        else:
            found.append(f"<{child_name or child.tag}> is not allowed inside <{name}>")
    if (
        rules["title"]
        and [_local_name(child.tag) for child in element].count("title") != 1
    ):
        found.append(f"<{name}> needs exactly one <title>")
    return found


def _attribute_name(key):
    """The schema's name for an attribute, or None for a namespace it does not use."""
    if not key.startswith("{"):
        return key
    namespace, _, local = key[1:].partition("}")
    return f"xml:{local}" if namespace == XML else None


def _attributes(element_name, element, rules):
    found = []
    for key, value in element.attrib.items():
        name = _attribute_name(key)
        if name not in rules["attributes"]:
            found.append(f"attribute {key} is not allowed on <{element_name}>")
            continue
        closed = rules["attributes"][name]
        if closed is not None and value not in closed:
            found.append(
                f'{name}="{value}" on <{element_name}> must be one of {", ".join(closed)}'
            )
        references = (
            [value]
            if name == "href"
            else re.findall(r"url\(\s*['\"]?([^)'\"]*)", value)
        )
        found += [
            f"<{element_name}> refers outside the document ({ref})"
            for ref in references
            if not ref.startswith("#")
        ]
    missing = [name for name in rules["required"] if name not in element.attrib]
    return found + [
        f"<{element_name}> lacks the required attribute {name}" for name in missing
    ]
