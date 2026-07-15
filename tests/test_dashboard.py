"""Dashboard tests via textual's pilot — headless, no real terminal."""

from pathlib import Path

from textual.widgets import DataTable

from sentryd.core.alerts import Alert, Severity
from sentryd.dashboard.app import AlertDetail, DashboardApp
from sentryd.storage.store import AlertStore

FIXTURES = Path(__file__).parent / "fixtures"


def seed_store(db_path, n=3) -> None:
    store = AlertStore(db_path)
    try:
        for i in range(n):
            store.insert(
                Alert(
                    rule_id="port_scan",
                    severity=Severity.HIGH,
                    confidence=0.9,
                    title=f"scan number {i}",
                    ts=1000.0 + i,
                    src="10.0.0.66",
                    dst="10.0.0.9",
                    evidence={"i": i},
                )
            )
    finally:
        store.close()


async def test_browse_mode_shows_stored_alerts(tmp_path):
    db = tmp_path / "dash.db"
    seed_store(db, n=3)

    app = DashboardApp(db_path=db)
    async with app.run_test() as pilot:
        await pilot.pause()
        table = app.query_one(DataTable)
        assert table.row_count == 3


async def test_browse_mode_picks_up_new_alerts(tmp_path):
    db = tmp_path / "dash.db"
    seed_store(db, n=1)

    app = DashboardApp(db_path=db, poll_interval=0.05)
    async with app.run_test() as pilot:
        await pilot.pause()
        assert app.query_one(DataTable).row_count == 1

        seed_store(db, n=2)  # two more land while the dashboard is open
        await pilot.pause(0.2)
        assert app.query_one(DataTable).row_count == 3


async def test_enter_opens_detail_screen(tmp_path):
    db = tmp_path / "dash.db"
    seed_store(db, n=1)

    app = DashboardApp(db_path=db)
    async with app.run_test() as pilot:
        await pilot.pause()
        app.query_one(DataTable).focus()
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, AlertDetail)
        assert app.screen.alert.title == "scan number 0"
        await pilot.press("escape")
        await pilot.pause()
        assert not isinstance(app.screen, AlertDetail)


async def test_playback_mode_streams_alerts_from_pcap(tmp_path):
    db = tmp_path / "dash.db"

    # speed=0 -> no pacing sleeps; the worker rips through the capture.
    app = DashboardApp(db_path=db, pcap=FIXTURES / "portscan.pcap", speed=0)
    async with app.run_test() as pilot:
        for _ in range(50):
            await pilot.pause(0.1)
            if app._replay_done and app._queue.empty():
                break
        await pilot.pause(0.3)
        table = app.query_one(DataTable)
        assert table.row_count == 3  # same alerts the headless replay finds

    store = AlertStore(db)
    try:
        assert len(store.list()) == 3  # playback persisted them too
    finally:
        store.close()
