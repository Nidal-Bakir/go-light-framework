package session

import (
	"context"
	"time"

	"github.com/Nidal-Bakir/go-todo-backend/internal/database"
	"github.com/Nidal-Bakir/go-todo-backend/internal/database/database_queries"
	"github.com/Nidal-Bakir/go-todo-backend/internal/utils"
)

type dbStore struct {
	db *database.Service
}

func NewDBStore(db *database.Service) StoreProvider {
	return &dbStore{db}
}

func (s dbStore) StoreAttr(ctx context.Context, session string, expiresAfter time.Duration, fields ...string) error {
	l := len(fields)
	if l == 0 {
		return nil
	}
	utils.Assert(l%2 == 0, "fields must be key-value pairs")
	if l == 2 {
		return s.db.Queries.SessionStoreStoreAttr(
			ctx,
			database_queries.SessionStoreStoreAttrParams{
				Session:   session,
				AttrKey:   fields[0],
				AttrValue: fields[1],
				ExpiresAt: database.ToPgTypeTimestamptz(time.Now().UTC().Add(expiresAfter)),
			},
		)
	}
	arr := make([]database_queries.SessionStoreStoreAttrsParams, 0, l/2)
	for i := 0; i < l; i += 2 {
		arr = append(
			arr,
			database_queries.SessionStoreStoreAttrsParams{
				Session:   session,
				ExpiresAt: database.ToPgTypeTimestamptz(time.Now().UTC().Add(expiresAfter)),
				AttrKey:   fields[i],
				AttrValue: fields[i+1],
			})
	}
	_, err := s.db.Queries.SessionStoreStoreAttrs(
		ctx,
		arr,
	)
	return err
}

func (s dbStore) GetAttr(ctx context.Context, session, key string) (string, error) {
	res, err := s.db.Queries.SessionStoreGetAttr(
		ctx,
		database_queries.SessionStoreGetAttrParams{
			Session: session,
			AttrKey: key,
		},
	)
	if err != nil {
		if database.IsErrPgxNoRows(err) {
			return "", nil
		}
		return "", err
	}
	return res.String, nil
}

func (s dbStore) RemoveAttr(ctx context.Context, session, key string) error {
	return s.db.Queries.SessionStoreRemoveAttr(
		ctx,
		database_queries.SessionStoreRemoveAttrParams{
			Session: session,
			AttrKey: key,
		},
	)
}
