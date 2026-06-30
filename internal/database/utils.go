package database

import (
	"context"
	"errors"
	"time"

	"github.com/Nidal-Bakir/go-todo-backend/internal/database/database_queries"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func UseTransaction(ctx context.Context, db *Service, fn func(queries *database_queries.Queries) error) error {
	tx, err := db.ConnPool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}

	defer func() {
		rollbackFn := func() {
			rollBackErr := tx.Rollback(ctx)
			err = errors.Join(rollBackErr, ctx.Err(), err)
		}
		commitFn := func() {
			commitErr := tx.Commit(ctx)
			err = errors.Join(commitErr, err)
		}

		select {
		case <-ctx.Done():
			rollbackFn()
		default:
			if err != nil {
				rollbackFn()
			} else {
				commitFn()
			}
		}
	}()

	queries := db.Queries.WithTx(tx)
	err = fn(queries)
	return err
}

func IsErrPgxNoRows(err error) bool {
	return errors.Is(err, pgx.ErrNoRows)
}

func ToPgTypeText(str string) pgtype.Text {
	return pgtype.Text{String: str, Valid: len(str) != 0}
}

func ToPgTypeTimestamp(t time.Time) pgtype.Timestamp {
	return pgtype.Timestamp{Time: t, Valid: !t.IsZero()}
}

func ToPgTypeTimestamptz(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: !t.IsZero()}
}

func ToPgTypeUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: uuid.Nil != id}
}

func PointerToPgTypeInt4(num *int32) pgtype.Int4 {
	if num == nil {
		return pgtype.Int4{Int32: -1, Valid: false}
	}
	return pgtype.Int4{Int32: int32(*num), Valid: true}
}

func ToPgTypeInt4(num int32) pgtype.Int4 {
	return pgtype.Int4{Int32: num, Valid: true}
}
