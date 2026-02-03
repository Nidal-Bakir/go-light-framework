package server

import (
	"context"

	"github.com/Nidal-Bakir/go-todo-backend/internal/database"
	"github.com/go-co-op/gocron/v2"
)

func (s *Server) registerCronJobs(ctx context.Context) {
	s._otpChallengeDeleteExpiredRows(ctx)
	s._sessionDeleteExpiredRows(ctx)
}

func (s *Server) _otpChallengeDeleteExpiredRows(ctx context.Context) {
	s.cronScheduler.NewJob(
		gocron.CronJob("0 2 * * *", false), // At 02:00 AM UTC
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

func (s *Server) _sessionDeleteExpiredRows(ctx context.Context) {
	s.cronScheduler.NewJob(
		gocron.CronJob("0 2 * * *", false), // At 02:00 AM UTC
		gocron.NewTask(
			func(ctx context.Context, db *database.Service) error {
				return db.Queries.SessionDeleteExpiredRows(ctx)
			},
			s.db,
		),
		gocron.WithContext(ctx),
		gocron.WithSingletonMode(gocron.LimitModeReschedule),
		gocron.WithName("Sessions Delete Expired Rows"),
	)
}
