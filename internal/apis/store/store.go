package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Brain-Wave-Ecosystem/auth-service/internal/models"
	apperrors "github.com/Brain-Wave-Ecosystem/go-common/pkg/error"
	"github.com/redis/go-redis/v9"
	"time"
)

const (
	refreshTokenPattern = "refresh_token:%s"
	confirmTokenPattern = "confirm_token:%s"

	confirmCodeTimeLive = time.Minute * 5
)

type Store struct {
	rdb *redis.Client
}

func NewStore(client *redis.Client) *Store {
	return &Store{
		rdb: client,
	}
}

func (s *Store) SaveRefreshToken(ctx context.Context, userID int64, role, refreshToken string, expirationTime time.Duration) error {
	key := fmt.Sprintf(refreshTokenPattern, refreshToken)

	data := &models.RefreshToken{
		UserID: userID,
		Role:   role,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return apperrors.Internal(err)
	}

	err = s.rdb.Set(ctx, key, jsonData, expirationTime).Err()
	if err != nil {
		return apperrors.InternalWithoutStackTrace(fmt.Errorf("failed to save refresh token: %w", err))
	}

	return nil
}

func (s *Store) SaveConfirmCode(ctx context.Context, userID int64, email string, name string, confirmCode int) error {
	var data *models.ConfirmCode
	key := fmt.Sprintf(confirmTokenPattern, email)

	codeData, err := s.rdb.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		data = &models.ConfirmCode{
			UserID: userID,
			Name:   name,
			Code:   confirmCode,
		}

		var jsonData []byte
		jsonData, err = json.Marshal(data)
		if err != nil {
			return apperrors.Internal(err)
		}

		err = s.rdb.Set(ctx, key, jsonData, confirmCodeTimeLive).Err()
		if err != nil {
			return apperrors.InternalWithoutStackTrace(err)
		}

		return nil
	} else if err != nil {
		return apperrors.InternalWithoutStackTrace(fmt.Errorf("failed to fetch confirm code: %w", err))
	}

	err = json.Unmarshal([]byte(codeData), &data)
	if err != nil {
		return apperrors.Internal(err)
	}

	data.Code = confirmCode

	jsonData, err := json.Marshal(data)
	if err != nil {
		return apperrors.Internal(err)
	}

	err = s.rdb.Set(ctx, key, jsonData, confirmCodeTimeLive).Err()
	if err != nil {
		return apperrors.InternalWithoutStackTrace(fmt.Errorf("failed to save confirm token: %w", err))
	}

	return nil
}

func (s *Store) ValidateRefreshToken(ctx context.Context, refreshToken string) (*models.RefreshToken, error) {
	key := fmt.Sprintf(refreshTokenPattern, refreshToken)

	data, err := s.rdb.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return nil, apperrors.InternalWithoutStackTrace(fmt.Errorf("invalid or expired refresh token"))
	} else if err != nil {
		return nil, apperrors.InternalWithoutStackTrace(fmt.Errorf("failed to validate refresh token: %w", err))
	}

	var token models.RefreshToken
	err = json.Unmarshal([]byte(data), &token)
	if err != nil {
		return nil, apperrors.Internal(err)
	}

	return &token, nil
}

func (s *Store) ValidateConfirmCode(ctx context.Context, email string) (*models.ConfirmCode, error) {
	key := fmt.Sprintf(confirmTokenPattern, email)

	data, err := s.rdb.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return nil, apperrors.InternalWithoutStackTrace(fmt.Errorf("invalid or expired confirm code"))
	} else if err != nil {
		return nil, apperrors.InternalWithoutStackTrace(fmt.Errorf("failed to validate confirm code: %w", err))
	}

	var confirmData models.ConfirmCode
	err = json.Unmarshal([]byte(data), &confirmData)
	if err != nil {
		return nil, apperrors.Internal(err)
	}

	return &confirmData, nil
}

func (s *Store) RemoveRefreshToken(ctx context.Context, refreshToken string) error {
	key := fmt.Sprintf(refreshTokenPattern, refreshToken)
	return s.rdb.Del(ctx, key).Err()
}

func (s *Store) RemoveConfirmCode(ctx context.Context, email string) error {
	key := fmt.Sprintf(confirmTokenPattern, email)
	return s.rdb.Del(ctx, key).Err()
}
