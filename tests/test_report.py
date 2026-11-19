"""What a walkthrough says: accurate about who saw what, and never breaking a timestamp.   # draft: #undetectable, #examples"""

import io
from contextlib import redirect_stdout

from diem import report, zones
from diem.sources import InMemoryDNS
from diem.validator import validate
from examples import pallet, pallet_world as pallets


def printed(function, *args):
    out = io.StringIO()
    with redirect_stdout(out):
        function(*args)
    return out.getvalue()


def test_a_server_that_saw_only_the_emblems_label_in_another_name_is_still_said_to_have_seen_it():
    world = zones.build(pallets.hierarchy(pallets.consignment()), pallets.NOW)
    source = InMemoryDNS(world)
    validate(pallet.customs_task(world), source, pallets.NOW)
    saw = printed(report.who_saw, source.log, pallets.CONSIGNMENT_NAME)
    assert (
        "the forwarder's live server"
        in saw.split("saw the emblem's own label")[0].split("; ")[-1]
    )


def test_a_stretch_of_two_steps_is_said_with_and():
    assert report._range([8, 9]) == "Steps 8 and 9"
    assert report._range([3, 4, 5]) == "Steps 3 to 5"
    assert report._range([6]) == "Step 6"


def test_a_heading_never_breaks_inside_its_timestamp():
    text = "Variant: ten days later, the staple's signatures have expired   (2026-11-27 12:00 UTC)"
    for width_filler in ("", "x " * 3, "y " * 8, "z" * 20 + " "):
        lines = printed(report.heading, width_filler + text).splitlines()
        assert any("(2026-11-27 12:00 UTC)" in line for line in lines)


def test_a_zone_or_record_is_printed_with_its_final_dot_whichever_way_it_is_given():
    assert "  a.example.  EMBLEM  (x)" in printed(
        report.listed, "a.example", "EMBLEM", "x"
    )
    assert "  a.example.  EMBLEM  (x)" in printed(
        report.listed, "a.example.", "EMBLEM", "x"
    )
