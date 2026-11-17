"""Direct unit tests for the coverage denominator.

The whole-branch review's mechanism finding: every prior fix injected a
record for one specific absence someone thought of, but `is_degraded` was
still `any()` over results, so anything that never became a StageResult
could never degrade a run -- there was no denominator. `Coverage` supplies
it. These tests exercise `is_degraded` directly, against the exact shapes
the review named: a target the scope guard refused (no StageResult at all,
just a refusal record elsewhere) and a stage dropped from the results list
entirely (e.g. one never reached because an earlier stage aborted the run).
"""
from sweeper.stages.base import Coverage, FailureClass, StageResult, is_degraded


def test_full_coverage_and_clean_results_is_not_degraded():
    coverage = Coverage(targets_requested=2, targets_permitted=2,
                        stages_requested=["dnsx", "naabu"])
    results = [
        StageResult(stage="dnsx", status="complete"),
        StageResult(stage="naabu", status="complete"),
    ]
    assert is_degraded(results, coverage) is False


def test_a_refused_target_degrades_the_run_even_with_every_stage_complete():
    """The exact shape of the mechanism finding: a scope refusal produces no
    StageResult at all, so `any()` over results alone can never see it. Only
    the denominator can."""
    coverage = Coverage(targets_requested=2, targets_permitted=1,
                        stages_requested=["dnsx"])
    results = [StageResult(stage="dnsx", status="complete")]
    assert is_degraded(results, coverage) is True


def test_a_requested_stage_missing_from_results_degrades_the_run():
    """A stage dropped from the results list entirely (never reached because
    an earlier stage aborted the run, say) has no StageResult to react to --
    only comparing against what was requested catches it."""
    coverage = Coverage(targets_requested=1, targets_permitted=1,
                        stages_requested=["dnsx", "naabu"])
    results = [StageResult(stage="dnsx", status="complete")]   # naabu absent
    assert is_degraded(results, coverage) is True


def test_a_failed_stage_still_degrades_with_full_coverage():
    """The pre-existing per-result rule must survive unchanged."""
    coverage = Coverage(targets_requested=1, targets_permitted=1,
                        stages_requested=["dnsx"])
    results = [StageResult(stage="dnsx", status="failed",
                           failure=FailureClass.TRANSPORT)]
    assert is_degraded(results, coverage) is True


def test_no_input_skip_with_full_coverage_is_not_degraded():
    """NO_INPUT is a correct outcome (nothing to consume), and the
    coverage checks do not turn it into one when the denominator is
    satisfied."""
    coverage = Coverage(targets_requested=1, targets_permitted=1,
                        stages_requested=["naabu"])
    results = [StageResult(stage="naabu", status="skipped",
                           failure=FailureClass.NO_INPUT)]
    assert is_degraded(results, coverage) is False


def test_default_coverage_does_not_spuriously_degrade():
    """A caller that has not populated coverage (Coverage()'s zero/empty
    default) must not have that absence itself read as a gap -- 0 permitted
    of 0 requested, and no stages requested, compares equal."""
    coverage = Coverage()
    results = [StageResult(stage="dnsx", status="complete")]
    assert is_degraded(results, coverage) is False
