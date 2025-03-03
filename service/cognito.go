package service

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/cbartram/hearthhub-common/model"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"math/big"
	"os"
	"path/filepath"
)

const (
	// Minimum password requirements based on AWS Cognito defaults
	minLength    = 8
	upperChars   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lowerChars   = "abcdefghijklmnopqrstuvwxyz"
	numberChars  = "0123456789"
	specialChars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
)

type CognitoService interface {
	UpdateUserAttributes(ctx context.Context, accessToken *string, attributes []types.AttributeType) error
	CreateCognitoUser(ctx context.Context, createUserPayload *CognitoCreateUserRequest) (*types.AuthenticationResultType, error)
	RefreshSession(ctx context.Context, discordID string) (*CognitoCredentials, error)
	AuthUser(ctx context.Context, refreshToken, userId *string, db *gorm.DB) (*model.User, error)
}

type CognitoServiceImpl struct {
	cognitoClient *cognitoidentityprovider.Client
	userPoolID    string
	clientID      string
	clientSecret  string
	configPath    string
}

type CognitoCredentials struct {
	RefreshToken    string `json:"refresh_token,omitempty"`
	TokenExpiration int32  `json:"token_expiration_seconds,omitempty"`
	AccessToken     string `json:"access_token,omitempty"`
	IdToken         string `json:"id_token,omitempty"`
}

type CognitoCreateUserRequest struct {
	DiscordID       string `json:"discord_id"`
	DiscordUsername string `json:"discord_username"`
	DiscordEmail    string `json:"discord_email"`
	AvatarId        string `json:"avatar_id"`
}

// MakeCognitoService creates a new instance of CognitoAuthManager
func MakeCognitoService(awsConfig aws.Config) CognitoService {
	return &CognitoServiceImpl{
		cognitoClient: cognitoidentityprovider.NewFromConfig(awsConfig),
		userPoolID:    os.Getenv("USER_POOL_ID"),
		clientID:      os.Getenv("COGNITO_CLIENT_ID"),
		clientSecret:  os.Getenv("COGNITO_CLIENT_SECRET"),
		configPath:    filepath.Join(os.Getenv("HOME"), ".config", "hearthhub-api", "session.json"),
	}
}

func (m *CognitoServiceImpl) UpdateUserAttributes(ctx context.Context, accessToken *string, attributes []types.AttributeType) error {
	_, err := m.cognitoClient.UpdateUserAttributes(ctx, &cognitoidentityprovider.UpdateUserAttributesInput{
		AccessToken:    accessToken,
		UserAttributes: attributes,
	})

	if err != nil {
		log.Errorf("could not update user attributes with access token: %s", err)
		return err
	}

	return nil
}

func (m *CognitoServiceImpl) CreateCognitoUser(ctx context.Context, createUserPayload *CognitoCreateUserRequest) (*types.AuthenticationResultType, error) {
	password, _ := GeneratePassword(PasswordConfig{
		Length:         15,
		RequireUpper:   true,
		RequireLower:   true,
		RequireNumber:  true,
		RequireSpecial: true,
	})

	attributes := []types.AttributeType{
		{
			Name:  aws.String("email"),
			Value: aws.String(createUserPayload.DiscordEmail),
		},
		{
			Name:  aws.String("custom:discord_id"),
			Value: aws.String(createUserPayload.DiscordID),
		},
		{
			Name:  aws.String("custom:discord_username"),
			Value: aws.String(createUserPayload.DiscordUsername),
		},
		{
			Name:  aws.String("custom:avatar_id"),
			Value: aws.String(createUserPayload.AvatarId),
		},
		{
			Name:  aws.String("custom:temporary_password"),
			Value: aws.String(password),
		},
		{
			Name:  aws.String("custom:refresh_token"),
			Value: aws.String("nil"),
		},
	}

	_, err := m.cognitoClient.AdminCreateUser(ctx, &cognitoidentityprovider.AdminCreateUserInput{
		UserPoolId:        aws.String(m.userPoolID),
		Username:          aws.String(createUserPayload.DiscordID),
		UserAttributes:    attributes,
		MessageAction:     types.MessageActionTypeSuppress,
		TemporaryPassword: aws.String(password),
	})

	if err != nil {
		return nil, fmt.Errorf("error creating user: %w", err)
	}

	// Set permanent password although users will never actually log in with a user/pass combo. The service will use the Cognito refresh token
	// to try and get an access token for the user and authenticate with the access token.
	_, err = m.cognitoClient.AdminSetUserPassword(ctx, &cognitoidentityprovider.AdminSetUserPasswordInput{
		UserPoolId: aws.String(m.userPoolID),
		Username:   aws.String(createUserPayload.DiscordID),
		Password:   aws.String(password),
		Permanent:  true,
	})
	if err != nil {
		return nil, fmt.Errorf("error setting permanent password: %w", err)
	}

	return m.initiateAuthUserPass(ctx, createUserPayload.DiscordID, password)
}

// initiateAuthUserPass Happens when a user is initially created with the user pool and uses username + generated pass to login
// The cognito refresh token and access token will be returned in the response along with the discord refresh and access
// token.
func (m *CognitoServiceImpl) initiateAuthUserPass(ctx context.Context, discordID, password string) (*types.AuthenticationResultType, error) {
	result, err := m.cognitoClient.AdminInitiateAuth(ctx, &cognitoidentityprovider.AdminInitiateAuthInput{
		UserPoolId: aws.String(m.userPoolID),
		ClientId:   aws.String(m.clientID),
		AuthFlow:   types.AuthFlowTypeAdminUserPasswordAuth,
		AuthParameters: map[string]string{
			"USERNAME":    discordID,
			"PASSWORD":    password,
			"SECRET_HASH": makeSecretHash(discordID, m.clientID, m.clientSecret),
		},
	})

	if err != nil {
		return nil, fmt.Errorf("error initiating admin user/pass auth with user pool: %w", err)
	}

	// Add refresh token as custom attribute. This enables admins to get credentials on behalf of a user
	attributes := make([]types.AttributeType, 0)
	attrName := "custom:refresh_token"
	attributes = append(attributes, types.AttributeType{
		Name:  &attrName,
		Value: result.AuthenticationResult.RefreshToken,
	})

	err = m.UpdateUserAttributes(ctx, result.AuthenticationResult.AccessToken, attributes)
	if err != nil {
		return nil, err
	}

	return result.AuthenticationResult, nil
}

// RefreshSession This method is called when a refresh token is about to expire and a new one needs to be generated.
// There is no direct way to get a new refresh token without a users password. Since we do not store the password we set
// must reset the password and re-auth to get a new refresh token.
func (m *CognitoServiceImpl) RefreshSession(ctx context.Context, discordID string) (*CognitoCredentials, error) {
	user, err := m.cognitoClient.AdminGetUser(ctx, &cognitoidentityprovider.AdminGetUserInput{
		UserPoolId: aws.String(m.userPoolID),
		Username:   &discordID,
	})

	if err != nil {
		log.Errorf("error: failed to get user attributes with for discord id: %s", discordID)
		return nil, errors.New(fmt.Sprintf("error: failed to get user for discord id: %s", discordID))
	}

	var password string
	for _, attribute := range user.UserAttributes {
		if aws.ToString(attribute.Name) == "custom:temporary_password" {
			password = aws.ToString(attribute.Value)
		}
	}

	log.Infof("auth user: %s with password", discordID)
	auth, err := m.initiateAuthUserPass(ctx, discordID, password)

	if err != nil {
		log.Errorf("error: failed to auth with user/pass for discord id: %s", discordID)
		return nil, errors.New(fmt.Sprintf("error: failed to auth with user/pass for discord id: %s", discordID))
	}

	return &CognitoCredentials{
		RefreshToken:    *auth.RefreshToken,
		TokenExpiration: auth.ExpiresIn,
		AccessToken:     *auth.AccessToken,
		IdToken:         *auth.IdToken,
	}, nil

}

func (m *CognitoServiceImpl) AuthUser(ctx context.Context, refreshToken, userId *string, db *gorm.DB) (*model.User, error) {
	auth, err := m.cognitoClient.AdminInitiateAuth(ctx, &cognitoidentityprovider.AdminInitiateAuthInput{
		UserPoolId: aws.String(m.userPoolID),
		ClientId:   aws.String(m.clientID),
		AuthFlow:   types.AuthFlowTypeRefreshTokenAuth,
		AuthParameters: map[string]string{
			"REFRESH_TOKEN": *refreshToken,
			"SECRET_HASH":   makeSecretHash(*userId, m.clientID, m.clientSecret),
		},
	})

	if err != nil {
		log.Errorf("error auth: user %s could not be authenticated: %v", *userId, err)
		return nil, err
	}

	user, err := model.GetUser(*userId, db)
	if err != nil {
		log.Errorf("could not get user from db: %v", err)
		return nil, err
	}

	user.Credentials = model.CognitoCredentials{
		AccessToken:     *auth.AuthenticationResult.AccessToken,
		RefreshToken:    *refreshToken,
		TokenExpiration: auth.AuthenticationResult.ExpiresIn,
		IdToken:         *auth.AuthenticationResult.IdToken,
	}
	// Note: Subscription limits are fetched at the API route handler layer because the data is stored in stripe and
	// not all users are subscribed adding a stripe API call here would be wasteful and may cause issues for a non-existent stripe user.
	return user, nil
}

// PasswordConfig holds the configuration for password generation
type PasswordConfig struct {
	Length         int
	RequireUpper   bool
	RequireLower   bool
	RequireNumber  bool
	RequireSpecial bool
}

// makeSecretHash Creates a hash based on the user id, service id and secret which must be
// sent with every cognito auth request (along with a refresh token) to get a new access token.
func makeSecretHash(userId, clientId, clientSecret string) string {
	usernameClientID := userId + clientId
	hash := hmac.New(sha256.New, []byte(clientSecret))
	hash.Write([]byte(usernameClientID))
	digest := hash.Sum(nil)

	return base64.StdEncoding.EncodeToString(digest)
}

// GeneratePassword generates a cryptographically secure password
func GeneratePassword(config PasswordConfig) (string, error) {
	if config.Length < minLength {
		return "", errors.New("password length must be at least 8 characters")
	}

	// Initialize the password builder with required characters
	var requiredChars []byte
	allChars := ""

	if config.RequireUpper {
		char, err := getRandomChar(upperChars)
		if err != nil {
			return "", err
		}
		requiredChars = append(requiredChars, char)
		allChars += upperChars
	}

	if config.RequireLower {
		char, err := getRandomChar(lowerChars)
		if err != nil {
			return "", err
		}
		requiredChars = append(requiredChars, char)
		allChars += lowerChars
	}

	if config.RequireNumber {
		char, err := getRandomChar(numberChars)
		if err != nil {
			return "", err
		}
		requiredChars = append(requiredChars, char)
		allChars += numberChars
	}

	if config.RequireSpecial {
		char, err := getRandomChar(specialChars)
		if err != nil {
			return "", err
		}
		requiredChars = append(requiredChars, char)
		allChars += specialChars
	}

	remainingLength := config.Length - len(requiredChars)
	if remainingLength < 0 {
		return "", errors.New("password length too short to satisfy requirements")
	}

	for i := 0; i < remainingLength; i++ {
		char, err := getRandomChar(allChars)
		if err != nil {
			return "", err
		}
		requiredChars = append(requiredChars, char)
	}

	password, err := shuffleBytes(requiredChars)
	if err != nil {
		return "", err
	}

	return string(password), nil
}

// Helper function to get a random character from a string
func getRandomChar(chars string) (byte, error) {
	if len(chars) == 0 {
		return 0, errors.New("character set is empty")
	}

	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
	if err != nil {
		return 0, err
	}

	return chars[n.Int64()], nil
}

// Helper function to securely shuffle a byte slice
func shuffleBytes(bytes []byte) ([]byte, error) {
	result := make([]byte, len(bytes))
	copy(result, bytes)

	for i := len(result) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return nil, err
		}
		j := n.Int64()
		result[i], result[j] = result[j], result[i]
	}

	return result, nil
}
