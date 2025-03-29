package service

import (
	"context"
	"encoding/json"
	auth "github.com/Brain-Wave-Ecosystem/auth-service/gen/auth"
	users "github.com/Brain-Wave-Ecosystem/auth-service/gen/users"
	"github.com/Brain-Wave-Ecosystem/auth-service/internal/apis/store"
	"github.com/Brain-Wave-Ecosystem/auth-service/internal/config"
	"github.com/Brain-Wave-Ecosystem/auth-service/internal/models"
	apperrors "github.com/Brain-Wave-Ecosystem/go-common/pkg/error"
	"github.com/Brain-Wave-Ecosystem/go-common/pkg/jwt"
	"github.com/Brain-Wave-Ecosystem/go-common/pkg/rabbits"
	"go.uber.org/zap"
	"go.uber.org/zap/buffer"
	"time"
)

type Service struct {
	usersClient users.UsersServiceClient
	jwt         *jwt.Service
	store       *store.Store
	publisher   rabbits.IPublisher
	logger      *zap.Logger
}

func NewService(usersClient users.UsersServiceClient, store *store.Store, publisher rabbits.IPublisher, logger *zap.Logger, cfg *config.Config) *Service {
	jwtService := jwt.NewService(cfg.JWT.Secret, cfg.JWT.AccessExpirationTime, cfg.JWT.RefreshExpirationTime)

	return &Service{
		usersClient: usersClient,
		jwt:         jwtService,
		store:       store,
		publisher:   publisher,
		logger:      logger,
	}
}

func (s *Service) Register(ctx context.Context, req *users.CreateUserRequest) (*auth.RegisterResponse, error) {
	res, err := s.usersClient.CreateUser(ctx, req)
	if err != nil {
		return nil, err
	}

	accessToken, err := s.jwt.GenerateToken(res.User.Id, res.User.Role)
	if err != nil {
		return nil, apperrors.Internal(err)
	}

	refreshToken, err := s.jwt.GenerateRefreshToken()
	if err != nil {
		return nil, apperrors.Internal(err)
	}

	err = s.store.SaveRefreshToken(ctx, res.User.Id, res.User.Role, refreshToken, s.jwt.GetRefreshExpiration())
	if err != nil {
		return nil, apperrors.Internal(err)
	}

	err = s.CreateEmailConfirmation(ctx, res.User.Id, res.User.Email, res.User.FullName)
	if err != nil {
		s.logger.Error("Failed to create email confirmation email", zap.String("email", res.User.Email), zap.Error(err))
	}

	result := &auth.RegisterResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User: &auth.User{
			Id:          res.User.Id,
			Email:       res.User.Email,
			AvatarUrl:   res.User.AvatarUrl,
			FullName:    res.User.FullName,
			Slug:        res.User.Slug,
			Bio:         res.User.Bio,
			LastLoginAt: res.User.LastLoginAt,
			Role:        res.User.Role,
			IsVerified:  res.User.IsVerified,
			UpdatedAt:   res.User.UpdatedAt,
			CreatedAt:   res.User.CreatedAt,
		},
	}

	return result, nil
}

func (s *Service) Login(ctx context.Context, req *auth.LoginRequest) (*auth.LoginResponse, error) {
	res, err := s.usersClient.LoginUserByEmail(ctx, &users.LoginUserByEmailRequest{Email: req.Email, Password: req.Password})
	if err != nil {
		return nil, err
	}

	accessToken, err := s.jwt.GenerateToken(res.User.Id, res.User.Role)
	if err != nil {
		return nil, apperrors.Internal(err)
	}

	refreshToken, err := s.jwt.GenerateRefreshToken()
	if err != nil {
		return nil, apperrors.Internal(err)
	}

	err = s.store.SaveRefreshToken(ctx, res.User.Id, res.User.Role, refreshToken, s.jwt.GetRefreshExpiration())
	if err != nil {
		return nil, apperrors.Internal(err)
	}

	result := &auth.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User: &auth.User{
			Id:          res.User.Id,
			Email:       res.User.Email,
			AvatarUrl:   res.User.AvatarUrl,
			FullName:    res.User.FullName,
			Slug:        res.User.Slug,
			Bio:         res.User.Bio,
			LastLoginAt: res.User.LastLoginAt,
			Role:        res.User.Role,
			IsVerified:  res.User.IsVerified,
			UpdatedAt:   res.User.UpdatedAt,
			CreatedAt:   res.User.CreatedAt,
		},
	}

	return result, nil
}

func (s *Service) RefreshToken(ctx context.Context, refreshToken string) (string, error) {
	tokeData, err := s.store.ValidateRefreshToken(ctx, refreshToken)
	if err != nil {
		return "", apperrors.Internal(err)
	}

	return s.jwt.GenerateToken(tokeData.UserID, tokeData.Role)
}

func (s *Service) VerifyUser(ctx context.Context, email string, confirmCode int) error {
	data, err := s.store.ValidateConfirmCode(ctx, email)
	if err != nil {
		s.logger.Warn("Failed to validate confirm code", zap.Error(err))
		return err
	}

	if data.Code != confirmCode {
		return apperrors.BadRequestHidden(err, "Confirm code is incorrect")
	}

	_, err = s.usersClient.ConfirmUser(ctx, &users.UserConfirmRequest{UserId: data.UserID})
	if err != nil {
		return err
	}

	_ = s.store.RemoveConfirmCode(ctx, email)

	var mail buffer.Buffer
	err = json.NewEncoder(&mail).Encode(models.SuccessConfirmEmailMail{
		Name:  data.Name,
		Email: email,
	})
	if err != nil {
		return apperrors.Internal(err)
	}

	err = s.publisher.Publish(ctx, rabbits.ExchangeKey, rabbits.SuccessConfirmUserEmailKey, &mail)
	if err != nil {
		return apperrors.Internal(err)
	}

	s.logger.Debug("Email send successfully", zap.String("email", email))

	return nil
}

func (s *Service) CreateEmailConfirmation(ctx context.Context, userID int64, email, name string) error {
	confirmCode := s.jwt.GenerateCode()
	saveCtx, saveCtxCancel := context.WithDeadline(ctx, time.Now().Add(time.Second+5))
	defer saveCtxCancel()

	err := s.store.SaveConfirmCode(saveCtx, userID, email, name, confirmCode)
	if err != nil {
		return apperrors.Internal(err)
	}

	var mail buffer.Buffer
	err = json.NewEncoder(&mail).Encode(&models.ConfirmEmailMail{
		Name:  name,
		Email: email,
		Code:  confirmCode,
		Time:  5,
	})
	if err != nil {
		return apperrors.Internal(err)
	}

	err = s.publisher.Publish(ctx, rabbits.ExchangeKey, rabbits.ConfirmUserEmailKey, &mail)
	if err != nil {
		return apperrors.Internal(err)
	}

	s.logger.Debug("Email send successfully", zap.String("email", email))

	return nil
}
