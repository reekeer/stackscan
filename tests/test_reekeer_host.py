"""How the CLI behaves when reekeer is hosting it rather than a terminal.

`embed.py` is covered by `test_embed.py`; this is the other half — the places where stackscan has to
*stop* doing something because it no longer owns the screen, and the one mode it has to refuse.
"""

from __future__ import annotations

import pytest

from stackscan import cli


@pytest.fixture
def hosted(monkeypatch: pytest.MonkeyPatch) -> None:
    """Bound at import time from the SDK or the environment; here it is simply set."""
    monkeypatch.setattr(cli, "is_reekeer", True)


def test_the_window_title_and_the_bell_are_left_alone(
    hosted: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    written: list[str] = []
    monkeypatch.setattr(cli.sys.stderr, "isatty", lambda: True)
    monkeypatch.setattr(cli.sys.stderr, "write", written.append)

    cli._set_title("scanning example.com")
    cli._bell()

    # The shell owns the terminal: an escape sequence would arrive as text to be printed, and the
    # prompt coming back is already the notification.
    assert written == []


def test_the_banner_is_not_drawn_over_help(hosted: None, monkeypatch: pytest.MonkeyPatch) -> None:
    drawn: list[object] = []
    monkeypatch.setattr(cli, "render_banner", lambda console: drawn.append(console))

    with pytest.raises(SystemExit) as exit_code:
        cli.main(["--help"])

    assert exit_code.value.code == 0
    assert drawn == [], "the shell printed its own wordmark at startup"


def test_runner_mode_is_refused_rather_than_started(
    hosted: None, capsys: pytest.CaptureFixture[str]
) -> None:
    # A worker loop inside the shell would hold an interpreter for the whole session and answer
    # nothing. Refusing has to happen before the import, or `aiohttp` is paid for anyway.
    assert cli.main(["--runner"]) == 2
    assert "outside the shell" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("args", "env", "wanted"),
    [
        ([], None, False),
        (["--runner"], None, True),
        (["https://example.com"], "1", True),
        (["https://example.com"], "on", True),
        (["https://example.com"], "0", False),
        (["https://example.com"], "", False),
    ],
)
def test_runner_is_asked_for_by_flag_or_environment(
    args: list[str], env: str | None, wanted: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("STACKSCAN_RUNNER", raising=False)
    if env is not None:
        monkeypatch.setenv("STACKSCAN_RUNNER", env)
    assert cli._wants_runner(args) is wanted


class _FakeBar:
    """Stands in for `reekeer.progress.Bar`, recording what it was told."""

    def __init__(self, label: str, total: int | None) -> None:
        self.label = label
        self.total = total
        self.done_count = 0
        self.steps: list[tuple[int, str]] = []
        self.finished: str | None = None

    def advance(self, steps: int = 1, label: str | None = None) -> _FakeBar:
        self.done_count += steps
        self.steps.append((steps, label or ""))
        return self

    def grow(self, extra: int) -> _FakeBar:
        if self.total is not None:
            self.total += extra
        return self

    def done(self, label: str | None = None) -> _FakeBar:
        self.finished = label or ""
        return self


def test_progress_is_reported_to_reekeer_instead_of_drawn(hosted: None) -> None:
    """The stage tracker feeds reekeer numbers when there is no `rich` display to feed.

    Which is the whole reason `reekeer.progress` exists: a `rich` live display is cursor movement,
    so inside the shell it renders nothing at all — a two-minute scan with no sign of life — and
    forced it would send one frame of escapes per update into a log that cannot replay them.
    """
    bar = _FakeBar("example.com", 4)
    tracker = cli._StageTracker(None, None, "https://example.com", 4, bar)

    tracker.info("starting...")
    tracker.stage("dns")
    tracker.reserve(2)
    tracker.advance("ports", steps=2)
    tracker.done("finished")

    # `info` says the same position with a new description and `reserve` only lengthens the bar;
    # `stage` and `advance` are the two that move it along.
    assert [steps for steps, _ in bar.steps] == [0, 1, 2]
    assert bar.done_count == 3
    # Work found half-way through raises the total rather than pinning the bar at the end.
    assert bar.total == 6
    assert bar.finished == "finished"
    # The label is the host: reekeer draws it in a pane a few inches wide, and the scheme is the
    # part that never varies from one line to the next.
    assert all(label.startswith("example.com") for _, label in bar.steps if label)


def test_a_tracker_without_reekeer_still_drives_rich(monkeypatch: pytest.MonkeyPatch) -> None:
    # Standalone the bar is `None` and nothing here may notice: the two are independent, and either
    # one being absent leaves the other doing all the work.
    updates: list[dict[str, object]] = []

    class _Progress:
        def update(self, task_id: object, **kwargs: object) -> None:
            updates.append(kwargs)

    tracker = cli._StageTracker(_Progress(), 1, "https://example.com", 4)
    tracker.stage("dns")
    tracker.done("finished")

    assert updates and updates[0]["advance"] == 1


def test_no_bar_is_asked_for_when_the_host_is_too_old(monkeypatch: pytest.MonkeyPatch) -> None:
    # `reekeer.progress` was added to the SDK after the rest of it, so a plugin can be newer than
    # the reekeer running it. That is an ordinary state, not a broken one.
    monkeypatch.setattr(cli, "_reekeer_progress", None)
    assert cli._bar("example.com", 4) is None
