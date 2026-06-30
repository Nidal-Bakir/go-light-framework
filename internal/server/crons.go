package server

import (
	"context"

	"github.com/Nidal-Bakir/go-todo-backend/internal/database"
	"github.com/go-co-op/gocron/v2"
)

func (s *Server) registerCronJobs(ctx context.Context) {
	s._otpChallengeDeleteExpiredRows(ctx)
	s._sessionDeleteExpiredRows(ctx)
	s._mfaSessionDeleteExpiredRows(ctx)
	s._mfaPendingSessionDeleteExpiredRows(ctx)
	s._mfaRememberedDevicesDeleteExpiredRows(ctx)
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
		gocron.JobOption(gocron.WithStartImmediately()),
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
		gocron.JobOption(gocron.WithStartImmediately()),
	)
}

func (s *Server) _mfaSessionDeleteExpiredRows(ctx context.Context) {
	s.cronScheduler.NewJob(
		gocron.CronJob("0 2 * * *", false), // At 02:00 AM UTC
		gocron.NewTask(
			func(ctx context.Context, db *database.Service) error {
				return db.Queries.MfaRemoveExpiredMfaSession(ctx)
			},
			s.db,
		),
		gocron.WithContext(ctx),
		gocron.WithSingletonMode(gocron.LimitModeReschedule),
		gocron.WithName("MFA Sessions Delete Expired Rows"),
		gocron.JobOption(gocron.WithStartImmediately()),
	)
}

func (s *Server) _mfaPendingSessionDeleteExpiredRows(ctx context.Context) {
	s.cronScheduler.NewJob(
		gocron.CronJob("0 2 * * *", false), // At 02:00 AM UTC
		gocron.NewTask(
			func(ctx context.Context, db *database.Service) error {
				return db.Queries.MfaRemoveExpiredPendingMfaSession(ctx)
			},
			s.db,
		),
		gocron.WithContext(ctx),
		gocron.WithSingletonMode(gocron.LimitModeReschedule),
		gocron.WithName("MFA Pending Sessions Delete Expired Rows"),
		gocron.JobOption(gocron.WithStartImmediately()),
	)
}

func (s *Server) _mfaRememberedDevicesDeleteExpiredRows(ctx context.Context) {
	s.cronScheduler.NewJob(
		gocron.CronJob("0 2 * * *", false), // At 02:00 AM UTC
		gocron.NewTask(
			func(ctx context.Context, db *database.Service) error {
				return db.Queries.MfaRemoveExpiredRememberedDevices(ctx)
			},
			s.db,
		),
		gocron.WithContext(ctx),
		gocron.WithSingletonMode(gocron.LimitModeReschedule),
		gocron.WithName("MFA Remembered Devices Delete Expired Rows"),
		gocron.JobOption(gocron.WithStartImmediately()),
	)
}
