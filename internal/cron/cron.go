package cron

import (
	"context"
	"time"

	"github.com/go-co-op/gocron/v2"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

func NewCronScheduler(ctx context.Context) gocron.Scheduler {
	zlog := zerolog.Ctx(ctx)

	scheduler, err := gocron.NewScheduler(
		gocron.WithGlobalJobOptions(
			gocron.WithContext(ctx),
			gocron.WithEventListeners(
				gocron.BeforeJobRuns(func(jobID uuid.UUID, jobName string) {
					zlog.Info().Str("job_name", jobName).Str("job_id", jobID.String()).Msg("job started")
				}),
				gocron.AfterJobRuns(func(jobID uuid.UUID, jobName string) {
					zlog.Info().Str("job_name", jobName).Str("job_id", jobID.String()).Msg("job finished")
				}),
				gocron.AfterJobRunsWithError(func(jobID uuid.UUID, jobName string, err error) {
					zlog.Err(err).Str("job_name", jobName).Str("job_id", jobID.String()).Msg("error while running the job")
				}),
				gocron.AfterJobRunsWithPanic(func(jobID uuid.UUID, jobName string, recoverData any) {
					zlog.Error().Str("job_name", jobName).Str("job_id", jobID.String()).Any("recover_data", recoverData).Msg("job panicked")
				}),
				gocron.AfterLockError(func(jobID uuid.UUID, jobName string, err error) {
					zlog.Err(err).Str("job_name", jobName).Str("job_id", jobID.String()).Msg("distributed locker returned an error")
				}),
			),
		),
		gocron.WithLogger(logger{l: zlog}),
		gocron.WithLocation(time.UTC),
	)
	if err != nil {
		zlog.Fatal().Err(err).Msg("Can't create new cron scheduler")
		return nil
	}
	scheduler.Start()
	return scheduler
}

type logger struct {
	l *zerolog.Logger
}

func (l logger) Debug(msg string, args ...any) {
	l.l.Debug().Msgf(msg, args...)
}
func (l logger) Error(msg string, args ...any) {
	l.l.Error().Msgf(msg, args...)
}
func (l logger) Info(msg string, args ...any) {
	l.l.Info().Msgf(msg, args...)
}
func (l logger) Warn(msg string, args ...any) {
	l.l.Warn().Msgf(msg, args...)
}
