package agent

import (
	"context"
	"database/sql"
	"errors"

	"github.com/Autumn-27/artex/db"
)

// The persisted mode controls which review workflow applies. A standalone
// exploration has no task mode, while a database failure must not turn a DeFi
// task into a generic task by accident.
func explicitDeFiTask(ts *db.ExplorationStore) bool {
	if ts == nil {
		return false
	}
	mode, err := ts.ReviewMode()
	if errors.Is(err, sql.ErrNoRows) {
		return false
	}
	return err != nil || mode == "defi"
}

type deFiTriggeredTaskKey struct{}

// The source task remains attached to reporter and retest follow-up turns so
// their report write path can verify that finding ownership has not changed.
func WithDeFiTriggeredTask(ctx context.Context, taskID int64) context.Context {
	return context.WithValue(ctx, deFiTriggeredTaskKey{}, taskID)
}

func deFiTriggeredTaskID(ctx context.Context) int64 {
	taskID, _ := ctx.Value(deFiTriggeredTaskKey{}).(int64)
	return taskID
}

func DeFiTriggeredTaskID(ctx context.Context) int64 { return deFiTriggeredTaskID(ctx) }
