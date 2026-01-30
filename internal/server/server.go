package server

import (
	"context"
	"fmt"
	"sync"

	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/Nidal-Bakir/go-todo-backend/internal/appenv"
	"github.com/Nidal-Bakir/go-todo-backend/internal/cron"

	"github.com/Nidal-Bakir/go-todo-backend/internal/database"
	"github.com/Nidal-Bakir/go-todo-backend/internal/gateway"
	"github.com/Nidal-Bakir/go-todo-backend/internal/l10n"
	redisdb "github.com/Nidal-Bakir/go-todo-backend/internal/redis_db"
	"github.com/Nidal-Bakir/go-todo-backend/internal/utils"
	"github.com/go-co-op/gocron/v2"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"golang.org/x/text/language"
)

var (
	serverPort      = os.Getenv("SERVER_PORT")
	FrontendDomains = appenv.DecodeEnvList(os.Getenv("FRONTEND_DOMAINS_LIST"))
)

type Server struct {
	port                    int
	db                      *database.Service
	rdb                     *redis.Client
	zlog                    *zerolog.Logger
	gatewaysProviderFactory gateway.ProviderFactory
	cronScheduler           gocron.Scheduler
}

func NewServer(ctx context.Context) (*http.Server, *Server) {
	zlog := zerolog.Ctx(ctx)

	l10n.InitL10n(
		ctx,
		"./l10n",
		[]language.Tag{
			utils.Must(language.Parse("en")),
			utils.Must(language.Parse("ar")),
		},
	)

	appServer := &Server{
		port:                    utils.Must(strconv.Atoi(serverPort)),
		db:                      database.NewConnection(ctx),
		rdb:                     redisdb.NewRedisClient(ctx),
		zlog:                    zlog,
		gatewaysProviderFactory: gateway.NewProviderFactory(ctx),
		cronScheduler:           cron.NewCronScheduler(ctx),
	}

	appServer.registerCronJobs(ctx)

	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", appServer.port),
		Handler:      appServer.RegisterRoutes(ctx),
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	return httpServer, appServer
}

func (s *Server) Shutdown(ctx context.Context) {
	s.zlog.Info().Msg("Starting application shutdown")
	wg := sync.WaitGroup{}

	wg.Go(func() {
		s.zlog.Info().Msg("Shutting down cron scheduler...")
		err := s.cronScheduler.Shutdown()
		if err != nil {
			s.zlog.Err(err).Msg("Error while shuting down the cron scheduler.")
		}
	})

	wg.Go(func() {
		s.zlog.Info().Msg("Closing database connections...")
		s.db.Close(ctx)
	})

	wg.Go(func() {
		s.zlog.Info().Msg("Closing Redis connections...")
		err := s.rdb.Close()
		if err != nil {
			s.zlog.Err(err).Msg("Error while closing the connection to redis.")
		}
	})

	wg.Wait()
}
