package rule

import (
	"context"
	"time"
)

// hFetchFailureLevel is how a failed rule-set fetch is logged. A fetch cut because its updater
// stopped (a reload or a restart of the service replaces the updater, and the new one fetches
// again at once) is not an error: debug. The first failures in a row are retried soon (the
// updater's backoff): a warning that says when. Only a rule set that keeps failing is an error. //H
func hFetchFailureLevel(stopped bool, failures int) string {
	switch {
	case stopped:
		return "debug"
	case failures <= hRuleSetFetchWarnings:
		return "warn"
	default:
		return "error"
	}
}

// hRuleSetFetchWarnings is how many failed fetches in a row are only warnings. //H
const hRuleSetFetchWarnings = 3

func hLogFetchFailure(updaterCtx context.Context, s *RemoteRuleSet, err error, retryIn time.Duration) {
	stopped := updaterCtx.Err() != nil || s.ctx.Err() != nil
	switch hFetchFailureLevel(stopped, s.retries) {
	case "debug":
		s.logger.Debug("fetch rule-set ", s.tag, " stopped by a reload: ", err)
	case "warn":
		s.logger.Warn("fetch rule-set ", s.tag, ": ", err, "; trying again in ", retryIn)
	default:
		s.logger.Error("fetch rule-set ", s.tag, ": ", err, "; trying again in ", retryIn)
	}
}
