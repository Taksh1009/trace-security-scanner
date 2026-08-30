import time

from modules.timing import StageTimer


def test_measure_records_duration():
    timer = StageTimer()
    with timer.measure("DNS"):
        time.sleep(0.01)

    assert timer.get("DNS") is not None
    assert timer.get("DNS") >= 10  # ms


def test_total_ms_sums_stages():
    timer = StageTimer()
    with timer.measure("A"):
        time.sleep(0.005)
    with timer.measure("B"):
        time.sleep(0.005)

    assert timer.total_ms() >= 10


def test_render_includes_stage_names_and_total():
    timer = StageTimer()
    with timer.measure("DNS"):
        pass
    output = timer.render()
    assert "DNS" in output
    assert "TOTAL" in output


def test_render_with_no_stages():
    timer = StageTimer()
    output = timer.render()
    assert "no stages recorded" in output
