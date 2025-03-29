package handler

import (
	"context"
	auth "github.com/Brain-Wave-Ecosystem/auth-service/gen/auth"
	users "github.com/Brain-Wave-Ecosystem/auth-service/gen/users"
	"github.com/Brain-Wave-Ecosystem/auth-service/internal/apis/service"
	apperrors "github.com/Brain-Wave-Ecosystem/go-common/pkg/error"

	"github.com/bufbuild/protovalidate-go"
	"go.uber.org/zap"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
)

var _ auth.AuthServiceServer = (*Handler)(nil)

type Handler struct {
	service   *service.Service
	logger    *zap.Logger
	validator protovalidate.Validator

	auth.UnimplementedAuthServiceServer
}

func NewHandler(service *service.Service, logger *zap.Logger) *Handler {
	v, _ := protovalidate.New(protovalidate.WithFailFast())

	return &Handler{
		service:   service,
		logger:    logger,
		validator: v,
	}
}

func (h *Handler) RegisterUser(ctx context.Context, request *auth.RegisterRequest) (*auth.RegisterResponse, error) {
	err := protovalidate.Validate(request)
	if err != nil {
		return nil, apperrors.ValidationError(err)
	}

	res, err := h.service.Register(ctx, &users.CreateUserRequest{
		Email:    request.GetEmail(),
		FullName: request.GetFullName(),
		Password: request.GetPassword(),
	})
	if err != nil {
		return nil, err
	}

	return res, err
}

func (h *Handler) VerifyUser(ctx context.Context, request *auth.VerifyUserRequest) (*emptypb.Empty, error) {
	return nil, h.service.VerifyUser(ctx, request.Email, int(request.ConfirmCode))
}

func (h *Handler) CreateConfirmUserCode(ctx context.Context, request *auth.CreateConfirmUserCodeRequest) (*emptypb.Empty, error) {
	return nil, h.service.CreateEmailConfirmation(ctx, -1, request.Email, request.FullName)
}

func (h *Handler) LoginUser(ctx context.Context, request *auth.LoginRequest) (*auth.LoginResponse, error) {
	err := h.validator.Validate(request)
	if err != nil {
		return nil, apperrors.ValidationError(err)
	}

	res, err := h.service.Login(ctx, request)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (h *Handler) RefreshToken(ctx context.Context, _ *auth.RefreshTokenRequest) (*auth.RefreshTokenResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, apperrors.Unauthorized("metadata is not provided")
	}

	data := md.Get("refresh_token")
	if len(data) == 0 {
		return nil, apperrors.Unauthorized("refresh_token is not provided")
	}

	refreshToken := data[0]
	accessToken, err := h.service.RefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, err
	}

	return &auth.RefreshTokenResponse{
		AccessToken: accessToken,
	}, nil
}
