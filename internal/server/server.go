package server

import (
	"context"
	"fmt"
	auth "github.com/Brain-Wave-Ecosystem/auth-service/gen/auth"
	users "github.com/Brain-Wave-Ecosystem/auth-service/gen/users"
	"github.com/Brain-Wave-Ecosystem/auth-service/internal/apis/handler"
	"github.com/Brain-Wave-Ecosystem/auth-service/internal/apis/service"
	"github.com/Brain-Wave-Ecosystem/auth-service/internal/apis/store"
	"github.com/Brain-Wave-Ecosystem/auth-service/internal/config"
	"github.com/Brain-Wave-Ecosystem/go-common/pkg/abstractions"
	"github.com/Brain-Wave-Ecosystem/go-common/pkg/clients"
	"github.com/Brain-Wave-Ecosystem/go-common/pkg/consul"
	"github.com/Brain-Wave-Ecosystem/go-common/pkg/grpcx/client"
	"github.com/Brain-Wave-Ecosystem/go-common/pkg/log"
	"github.com/Brain-Wave-Ecosystem/go-common/pkg/rabbits"
	"github.com/Brain-Wave-Ecosystem/go-common/pkg/resolver"
	"github.com/Brain-Wave-Ecosystem/go-common/pkg/telemetry/interceptors"
	"github.com/DavidMovas/gopherbox/pkg/closer"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"net"
)

var _ abstractions.Server = (*Server)(nil)

type Server struct {
	grpcServer *grpc.Server
	consul     *consul.Consul
	logger     *log.Logger
	cfg        *config.Config
	closer     *closer.Closer
}

func NewServer(_ context.Context, cfg *config.Config) (*Server, error) {
	cl := closer.NewCloser()

	logger, err := log.NewLogger(cfg.Local, cfg.LogLevel)
	if err != nil {
		return nil, fmt.Errorf("error initializing logger: %w", err)
	}

	cl.Push(logger.Stop)

	consulManager, err := consul.NewConsul(cfg.ConsulURL, cfg.Name, cfg.Address, cfg.GRPCPort, logger.Zap())
	if err != nil {
		logger.Zap().Error("error initializing consul manager", zap.Error(err))
		return nil, fmt.Errorf("error initializing consul manager: %w", err)
	}

	cl.Push(consulManager.Stop)

	grpcServer := grpc.NewServer(grpc.ChainUnaryInterceptor())

	healthServer := health.NewServer()
	healthServer.SetServingStatus(fmt.Sprintf("%s-%d", cfg.Name, cfg.GRPCPort), grpc_health_v1.HealthCheckResponse_SERVING)
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)

	cl.PushNE(healthServer.Shutdown)

	redis, err := clients.NewRedisClient(cfg.Redis.URL, nil)
	if err != nil {
		logger.Zap().Error("Failed to create redis client", zap.Error(err))
		return nil, err
	}

	cl.PushIO(redis)

	usersClient, err := client.NewServiceClientWithRetry[users.UsersServiceClient](
		cfg.UsersService.Address,
		users.NewUsersServiceClient,
		nil,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithResolvers(resolver.NewBuilder(consulManager.WatchService(cfg.UsersService.Address), logger.Zap())),
		grpc.WithUnaryInterceptor(interceptors.TraceTelemetryClientInterceptor(cfg.Name)),
	)
	if err != nil {
		logger.Zap().Error("Failed to create users client", zap.Error(err))
		//return nil, err
	}

	publisher, err := rabbits.NewPublisher(cfg.Rabbit.URL, rabbits.JSON,
		rabbits.WithExchange(rabbits.ExchangeKey, rabbits.ExchangeDirect, true, false, nil),
		rabbits.WithQueueAndBind(rabbits.ConfirmUserEmailQueueKey, rabbits.ConfirmUserEmailKey, rabbits.ExchangeKey, true, false, nil),
		rabbits.WithQueueAndBind(rabbits.SuccessConfirmUserEmailQueueKey, rabbits.SuccessConfirmUserEmailKey, rabbits.ExchangeKey, true, false, nil),
	)
	if err != nil {
		logger.Zap().Error("Failed to create rabbit publisher", zap.Error(err))
		// return nil, err
	}

	cl.PushIO(publisher)

	s := store.NewStore(redis)
	srv := service.NewService(usersClient, s, publisher, logger.Zap(), cfg)
	h := handler.NewHandler(srv, logger.Zap())

	auth.RegisterAuthServiceServer(grpcServer, h)

	return &Server{
		grpcServer: grpcServer,
		consul:     consulManager,
		logger:     logger,
		cfg:        cfg,
		closer:     cl,
	}, nil
}

func (s *Server) Start() error {
	z := s.logger.Zap()

	z.Info("Starting server", zap.String("name", s.cfg.Name), zap.Int("port", s.cfg.GRPCPort))

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", s.cfg.GRPCPort))
	if err != nil {
		z.Error("Failed to start listener", zap.String("name", s.cfg.Name), zap.Int("port", s.cfg.GRPCPort), zap.Error(err))
		return err
	}

	s.closer.PushIO(lis)

	err = s.consul.RegisterService()
	if err != nil {
		z.Error("Failed to register service in consul registry", zap.String("name", s.cfg.Name), zap.Error(err))
		return err
	}

	return s.grpcServer.Serve(lis)
}

func (s *Server) Shutdown(ctx context.Context) error {
	z := s.logger.Zap()

	z.Info("Shutting down server", zap.String("name", s.cfg.Name))

	s.grpcServer.GracefulStop()

	<-ctx.Done()
	s.grpcServer.Stop()

	return s.closer.Close(ctx)
}
