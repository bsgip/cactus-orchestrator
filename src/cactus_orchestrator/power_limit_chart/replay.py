"""Client knowledge replay.

The chart models what the CLIENT knows, not what the server stored. The client's view of a
group refreshes only at observation events: successful GETs of the group's DERControl list
(or DefaultDERControl) taken from the request history, or - for subscribed groups -
server-side changes (notifications assumed delivered at the moment of change).

Between observations the client executes the schedule it last saw: cancellations, value
updates and supersessions only take effect at the next observation that reveals them.

A group with DOEs/defaults but no poll attempts and no subscription is an error: a real
client that neither polls nor subscribes is non-compliant, and its knowledge cannot be
modelled. A group whose polls were attempted but ALL failed charts as having no knowledge -
a failed poll gives the client no new knowledge.
"""

import logging
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import partial
from typing import Protocol

from cactus_schema.runner.schema import RequestEntry

from cactus_orchestrator.power_limit_chart.db import _RawControlGroup, _RawDefault, _RawDOE

logger = logging.getLogger(__name__)

# Matches /edev/{n}/derp/{group_id}/derc list requests (with optional query string).
# Anchored so single-control GETs (/derc/{id}) do NOT count as list observations - they
# cannot reveal list-level additions, cancellations or supersessions.
_DERC_PATH_RE = re.compile(r"/edev/\d+/derp/(\d+)/derc(?:\?|$)")

# Matches /edev/{n}/derp/{group_id}/dderc (with optional query string)
_DDERC_PATH_RE = re.compile(r"/edev/\d+/derp/(\d+)/dderc(?:\?|$)")

# Sentinel for "still current" windows
_FAR_FUTURE = datetime(9999, 1, 1, tzinfo=UTC)


class _GroupScoped(Protocol):
    site_control_group_id: int


def _group_by_gid[RowT: _GroupScoped](rows: Iterable[RowT]) -> dict[int, list[RowT]]:
    result: dict[int, list[RowT]] = {}
    for row in rows:
        result.setdefault(row.site_control_group_id, []).append(row)
    return result


# ─── Server-side version reconstruction ───────────────────────────────────────


def _row_change_time(row: _RawDOE | _RawDefault) -> datetime:
    """When this row's values became the server's current state."""
    return row.created_time if isinstance(row, _RawDOE) else row.changed_time


def _boundary_time(row: _RawDOE | _RawDefault) -> datetime:
    """When this row's values stopped being the server's current state (_FAR_FUTURE if current).

    deleted_time is authoritative (aligned with the change that removed the row); archive_time
    is an auditing timestamp that approximates it. See envoy's ArchiveBase."""
    if not row.is_archive:
        return _FAR_FUTURE
    if row.deleted_time is not None:
        return row.deleted_time
    if row.archive_time is not None:
        return row.archive_time
    return _row_change_time(row)  # malformed archive row - zero-width, gets skipped


@dataclass
class _ControlVersion:
    """The values a DOE held on the server during [valid_from, valid_to)."""

    row: _RawDOE
    valid_from: datetime
    valid_to: datetime


def _build_control_versions(all_does: list[_RawDOE]) -> dict[int, list[_ControlVersion]]:
    """Reconstructs, per DOE, the sequence of LIVE value-versions the server held over time.

    Archive rows hold the values that applied up until their archive/deleted time; the
    active row (if any) holds the current values. Chaining those boundaries yields each
    version's validity window. Windows in which the server presented the DOE as superseded
    are omitted (the client sees no live control there), and after a deletion boundary the
    DOE no longer exists."""
    versions_by_id: dict[int, list[_ControlVersion]] = {}
    for doe_id, rows in _rows_by_doe_id(all_does).items():
        # Deterministic on boundary ties: a same-instant delete snapshot must sort after the
        # update snapshot it duplicates, so the pre-delete values claim the shared window.
        rows.sort(key=lambda r: (_boundary_time(r), r.deleted_time is not None))
        valid_from = min(r.created_time for r in rows)
        versions: list[_ControlVersion] = []
        for row in rows:
            valid_to = _boundary_time(row)
            if valid_to > valid_from:
                if not row.superseded:
                    versions.append(_ControlVersion(row=row, valid_from=valid_from, valid_to=valid_to))
                valid_from = valid_to
            if row.deleted_time is not None:
                break  # The DOE ceased to exist here; later rows are duplicate snapshots
        versions_by_id[doe_id] = versions
    return versions_by_id


def _rows_by_doe_id(all_does: list[_RawDOE]) -> dict[int, list[_RawDOE]]:
    result: dict[int, list[_RawDOE]] = {}
    for doe in all_does:
        result.setdefault(doe.dynamic_operating_envelope_id, []).append(doe)
    return result


def _version_at(versions: list[_ControlVersion], t: datetime) -> _ControlVersion | None:
    for v in versions:
        if v.valid_from <= t < v.valid_to:
            return v
    return None


def _live_row_at(versions: list[_ControlVersion], t: datetime) -> _RawDOE | None:
    version = _version_at(versions, t)
    return version.row if version is not None else None


def _default_version_at(rows: list[_RawDefault], t: datetime) -> _RawDefault | None:
    """The default row that was the server's current state at time t (latest changed_time wins)."""
    best: _RawDefault | None = None
    for row in rows:
        if row.changed_time <= t < _boundary_time(row):
            if best is None or row.changed_time > best.changed_time:
                best = row
    return best


# ─── Observations ─────────────────────────────────────────────────────────────


@dataclass
class _Observation:
    """A moment at which the client's knowledge of a group's server state refreshes."""

    time: datetime
    step_name: str = ""


@dataclass
class _PollHistory:
    """Client poll observations extracted from the request history, per group.

    derc/dderc hold successful (2xx GET) observations; the attempted sets record groups with
    ANY GET to the list endpoint regardless of status - a failed poll gives the client no new
    knowledge, but does prove the client was polling (so no instant-knowledge fallback)."""

    derc: dict[int, list[_Observation]] = field(default_factory=dict)
    dderc: dict[int, list[_Observation]] = field(default_factory=dict)
    derc_attempted: set[int] = field(default_factory=set)
    dderc_attempted: set[int] = field(default_factory=set)


def _collect_poll_observations(sorted_requests: list[RequestEntry]) -> _PollHistory:
    history = _PollHistory()
    for req in sorted_requests:
        if req.method != "GET":
            continue
        succeeded = 200 <= int(req.status) < 300
        observation = _Observation(req.timestamp, (req.step_name or "").strip())
        m = _DDERC_PATH_RE.search(req.path)
        if m:
            gid = int(m.group(1))
            history.dderc_attempted.add(gid)
            if succeeded:
                history.dderc.setdefault(gid, []).append(observation)
            continue
        m = _DERC_PATH_RE.search(req.path)
        if m:
            gid = int(m.group(1))
            history.derc_attempted.add(gid)
            if succeeded:
                history.derc.setdefault(gid, []).append(observation)
    return history


def _step_name_at(sorted_requests: list[RequestEntry], group_id: int, t: datetime) -> str:
    """The last non-empty step name on a request to this group's DERControl list at or before t."""
    step = ""
    for req in sorted_requests:
        if req.timestamp > t:
            break
        m = _DERC_PATH_RE.search(req.path)
        if m and int(m.group(1)) == group_id:
            name = (req.step_name or "").strip()
            if name:
                step = name
    return step


def _synthesize_observations(
    rows: Iterable[_RawDOE] | Iterable[_RawDefault], step_at: Callable[[datetime], str] | None = None
) -> list[_Observation]:
    """Instant-knowledge observations at every server-side change (creation and boundary).
    Used for subscribed groups (notifications assumed delivered at the moment of change)."""
    times: set[datetime] = set()
    for row in rows:
        times.add(_row_change_time(row))
        boundary = _boundary_time(row)
        if boundary < _FAR_FUTURE:
            times.add(boundary)
    return [_Observation(t, step_at(t) if step_at is not None else "") for t in sorted(times)]


def _assemble_observations(polls: list[_Observation], synthesized: list[_Observation]) -> list[_Observation]:
    """Merge and time-dedupe observations (first non-empty step name wins per instant)."""
    by_time: dict[datetime, _Observation] = {}
    for obs in polls + synthesized:
        existing = by_time.get(obs.time)
        if existing is None:
            by_time[obs.time] = obs
        elif not existing.step_name and obs.step_name:
            existing.step_name = obs.step_name
    return [by_time[t] for t in sorted(by_time)]


def _observations_for_groups[RowT: _GroupScoped](
    rows_by_group: dict[int, list[RowT]],
    polls_by_group: dict[int, list[_Observation]],
    attempted_group_ids: set[int],
    subscribed_group_ids: set[int],
    synthesize: Callable[[list[RowT], int], list[_Observation]],
    resource_label: str,
) -> dict[int, list[_Observation]]:
    """Assemble per-group observation events from polls and subscriptions.

    Raises ValueError for a group with rows but no poll attempts and no subscription -
    such a client is non-compliant and its knowledge cannot be modelled."""
    observations: dict[int, list[_Observation]] = {}
    for gid, rows in rows_by_group.items():
        polls = polls_by_group.get(gid, [])
        synthesized: list[_Observation] = []
        if gid in subscribed_group_ids:
            synthesized = synthesize(rows, gid)
        elif not polls and gid not in attempted_group_ids:
            raise ValueError(
                f"Group {gid} has {resource_label} entries but the client never polled the "
                f"{resource_label} list and holds no subscription - client knowledge cannot be modelled"
            )
        elif not polls:
            logger.warning(
                "power_limit_chart: all %s polls for group %d failed - client gains no knowledge",
                resource_label,
                gid,
            )
        observations[gid] = _assemble_observations(polls, synthesized)
    return observations


def _build_group_observations(
    all_does: list[_RawDOE],
    all_defaults: list[_RawDefault],
    sorted_requests: list[RequestEntry],
    subscribed_group_ids: set[int],
    default_subscribed_group_ids: set[int],
) -> tuple[dict[int, list[_Observation]], dict[int, list[_Observation]]]:
    """Returns (derc_observations_by_group, dderc_observations_by_group)."""
    history = _collect_poll_observations(sorted_requests)

    def synth_controls(rows: list[_RawDOE], gid: int) -> list[_Observation]:
        return _synthesize_observations(rows, partial(_step_name_at, sorted_requests, gid))

    def synth_defaults(rows: list[_RawDefault], gid: int) -> list[_Observation]:
        return _synthesize_observations(rows)

    derc_observations = _observations_for_groups(
        _group_by_gid(all_does),
        history.derc,
        history.derc_attempted,
        subscribed_group_ids,
        synth_controls,
        "DERControl",
    )
    dderc_observations = _observations_for_groups(
        _group_by_gid(all_defaults),
        history.dderc,
        history.dderc_attempted,
        default_subscribed_group_ids,
        synth_defaults,
        "DefaultDERControl",
    )
    return derc_observations, dderc_observations


# ─── Knowledge replay ─────────────────────────────────────────────────────────


@dataclass
class _Known[RowT]:
    """A server row as the client knew it during [known_from, known_until).

    known_from is the observation that revealed this row (version) to the client;
    step_name is the step active at that observation ("" if unknown)."""

    row: RowT
    known_from: datetime
    known_until: datetime
    step_name: str = ""


def _observed_spans[RowT](
    observations: list[_Observation], row_at: Callable[[datetime], RowT | None]
) -> list[_Known[RowT]]:
    """Walk a group's observations, returning the row-version the client believed over time.

    At each observation the client's belief becomes the server row at that instant; between
    observations the client keeps its last belief. Contiguous spans of the same row merge."""
    spans: list[_Known[RowT]] = []
    for i, obs in enumerate(observations):
        row = row_at(obs.time)
        if row is None:
            continue  # The client sees nothing live at this observation
        known_until = observations[i + 1].time if i + 1 < len(observations) else _FAR_FUTURE
        if spans and spans[-1].row is row and spans[-1].known_until >= obs.time:
            spans[-1].known_until = known_until
        else:
            spans.append(_Known(row=row, known_from=obs.time, known_until=known_until, step_name=obs.step_name))
    return spans


@dataclass
class _KnownControlSegment:
    """A window during which the client is executing one version of a DOE's schedule."""

    row: _RawDOE
    site_control_group_id: int
    primacy: int
    observed_at: datetime  # the observation that revealed this version to the client
    effective_start: datetime  # max(row.start_time, observed_at)
    effective_end: datetime
    step_name: str

    @property
    def label(self) -> str:
        return self.step_name or f"DERC{self.row.dynamic_operating_envelope_id}"


def _replay_control_knowledge(
    all_does: list[_RawDOE],
    observations_by_group: dict[int, list[_Observation]],
    groups_by_id: dict[int, _RawControlGroup],
    doe_tags: dict[int, str],
    test_start: datetime,
) -> list[_KnownControlSegment]:
    """Replays the client's knowledge of each DOE from its group's observation events.

    A control enters the client's world at the first observation that shows it. Between
    observations the client executes the schedule it last saw; a cancellation, supersession
    or value update only takes effect at the next observation that reveals it. A control the
    client never observed contributes nothing."""
    versions_by_id = _build_control_versions(all_does)
    segments: list[_KnownControlSegment] = []

    for doe_id, versions in versions_by_id.items():
        if not versions:
            continue
        first_row = versions[0].row
        group = groups_by_id.get(first_row.site_control_group_id)
        if group is None:
            continue
        # Only include controls created during the test
        if first_row.created_time < test_start:
            continue

        observations = observations_by_group.get(group.site_control_group_id, [])
        for span in _observed_spans(observations, partial(_live_row_at, versions)):
            row = span.row
            seg_start = max(row.start_time, span.known_from)
            seg_end = min(row.start_time + timedelta(seconds=row.duration_seconds), span.known_until)
            if seg_end <= seg_start:
                continue
            segments.append(
                _KnownControlSegment(
                    row=row,
                    site_control_group_id=group.site_control_group_id,
                    primacy=group.primacy,
                    observed_at=span.known_from,
                    effective_start=seg_start,
                    effective_end=seg_end,
                    # Prefer the tag recorded at control-creation time; fall back to the step
                    # name active at the observation that revealed this version.
                    step_name=doe_tags.get(doe_id, span.step_name),
                )
            )
    return segments


def _replay_default_knowledge(
    all_defaults: list[_RawDefault],
    observations_by_group: dict[int, list[_Observation]],
) -> dict[int, list[_Known[_RawDefault]]]:
    """Replays the client's knowledge of each group's default control from dderc observations."""
    known: dict[int, list[_Known[_RawDefault]]] = {}
    for group_id, rows in _group_by_gid(all_defaults).items():
        observations = observations_by_group.get(group_id, [])
        known[group_id] = _observed_spans(observations, partial(_default_version_at, rows))
    return known
