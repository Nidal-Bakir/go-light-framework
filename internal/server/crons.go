package server

import (
	"context"
	"time"

	"github.com/Nidal-Bakir/go-todo-backend/internal/database"
	"github.com/go-co-op/gocron/v2"
)

func (s *Server) registerCronJobs(ctx context.Context) {
	s.cronScheduler.NewJob(
		gocron.DurationJob(time.Hour),
		gocron.NewTask(
			func(ctx context.Context, db *database.Service) error {
				return db.Queries.OtpChallengeDeleteExpiredRows(ctx)
			},
			s.db,
		),
		gocron.WithContext(ctx),
		gocron.WithSingletonMode(gocron.LimitModeReschedule),
		gocron.WithName("Otp Challenge Delete Expired Rows"),
	)
}
