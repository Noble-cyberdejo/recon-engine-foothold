import time
import pytest

from recon_engine.ratelimit import RateLimiter, RequestBudget, BudgetExceeded


def test_rate_limiter_throttles_bursts():
    limiter = RateLimiter(rate_per_second=1000, burst=2)  # fast rate, tiny burst for a quick test
    calls = []

    def fake_sleep(seconds):
        calls.append(seconds)

    limiter.wait_for_slot(sleep_fn=fake_sleep)  # consumes 1 of 2 burst tokens, no sleep
    limiter.wait_for_slot(sleep_fn=fake_sleep)  # consumes 2nd token, no sleep
    limiter.wait_for_slot(sleep_fn=fake_sleep)  # bucket empty -> must wait
    assert len(calls) == 1
    assert calls[0] > 0


def test_request_budget_caps_at_240_by_default():
    budget = RequestBudget()
    assert budget.max_requests == 240
    budget.consume(240)
    assert budget.remaining() == 0
    with pytest.raises(BudgetExceeded):
        budget.consume(1)


def test_request_budget_tracks_partial_use():
    budget = RequestBudget(max_requests=10)
    budget.consume(3)
    assert budget.remaining() == 7
    budget.consume(7)
    assert budget.remaining() == 0