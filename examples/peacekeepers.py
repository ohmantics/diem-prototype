"""A peacekeeping mission, its people and its convoys.   # draft: #ex-peacekeepers

    python -m examples.peacekeepers

A mission marks its personnel for the duration of a deployment. Each person's
emblem is under an unguessable label that is replaced at every rotation, and
carries the mission, the person's protected status and a validity period, and
nothing that identifies the person. The deploying organization endorses the
mission. What a checkpoint should do with a badge that does not validate is in
the mission's own emblem, because nothing on a failed badge can be trusted.
A convoy's position is a dynamic facet, encrypted to those who may follow it.
"""

from diem import network, profile, report, times, validator, zones
from examples import peacekeepers_world as world_of
from examples.records import peacekeepers as records


def task(world, name, profile_name, authorities=(world_of.DEPLOYER,), **more):
    return validator.Task(
        emblem_name=name,
        how_named=(
            "read from the badge"
            if profile_name != "peacekeeping-convoy"
            else "known to the operations center"
        ),
        profile=profile.load(profile_name),
        evidence={"asset": name},
        trust_anchor=world.anchor,
        authorities=authorities,
        **more,
    )


def check(title, task, source, first=None):
    report.heading(f"{title}   ({times.moment(world_of.NOW)})")
    result = validator.validate(task, source, world_of.NOW)
    report.outcome(result, first)
    report.who_saw(source.log, task.emblem_name)
    return result


def introduction(world):
    print(
        "A peacekeeping mission marks its people and its convoys.   (draft #ex-peacekeepers)"
    )
    report.hierarchy(world.hierarchy)
    report.heading("The mission publishes a badge for each person, and its own emblem")
    report.published(world_of.BADGE, "EMBLEM", records.PERSONNEL)
    report.published(world_of.MISSION_NAME, "EMBLEM", records.MISSION)
    report.heading(
        "The deploying organization endorses the mission for what its badges ask and for "
        "what it says to do when one fails. The convoy's position is encrypted to the "
        "mission's operations center and the host state's liaison."
    )
    report.listed(world_of.CONVOY, "EMBLEM", "peacekeeping-convoy, online-signed")


def badge_runs(world, dns_source):
    badge = task(world, world_of.BADGE, "peacekeeping-personnel")
    first = check("A soldier at a checkpoint scans a badge", badge, dns_source())
    check(
        "Variant: a badge from the previous rotation, whose emblem was removed",
        task(world, world_of.OLD_BADGE, "peacekeeping-personnel"),
        dns_source(),
        first,
    )


def convoy_run(world, dns_source):
    convoy = check(
        "The operations center follows a convoy",
        task(
            world,
            world_of.CONVOY,
            "peacekeeping-convoy",
            keys=(world_of.OPERATIONS,),
            needs=("position",),
        ),
        dns_source(),
    )
    where = convoy.opened["position"]
    north = where["latitude"].to_decimal()
    west = abs(where["longitude"].to_decimal())
    report.heading(
        f"The operations center reads the position: {north} N, {west} W, "
        f"as of {times.moment(where['as-of'].seconds)} (a made-up position in open ocean)."
    )


def main():
    options = network.parse_options(__doc__)
    world = zones.build(world_of.hierarchy(), world_of.NOW)
    dns_source = network.dns_source(options, world)
    introduction(world)
    badge_runs(world, dns_source)
    convoy_run(world, dns_source)
    report.heading(
        "Privacy: through the resolver, the mission's emblem server saw each badge check "
        "above, and could map where its people are being checked. The profile should say "
        "whether that is wanted (stray reporting) or a risk to manage (draft #privacy)."
    )


if __name__ == "__main__":
    main()
