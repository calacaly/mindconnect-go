package agent

import (
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/calacaly/mindconnect-go/internal/api/agentmanagement/v3/client/registration_operations"
	"github.com/calacaly/mindconnect-go/internal/api/agentmanagement/v3/client/token_operations"
	"github.com/calacaly/mindconnect-go/internal/api/agentmanagement/v3/models"
	"github.com/calacaly/mindconnect-go/internal/utils"
	"github.com/calacaly/mindconnect-go/pkg/log"
	"github.com/calacaly/mindconnect-go/pkg/store"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

type Auther interface {
	SetClientIdentifier(clientIdentifier *models.ClientIdentifier)
	SetConfiguration(configuration *models.Configuration)
	SetAccessToken(accessToken *models.AccessToken)
	SetOauthPublicKey(oauthPublicKey *models.TokenKey)
	GetCertificate() (*models.TokenKey, error)
	GetClientIdentifier() *models.ClientIdentifier
	OnBoard() (*models.ClientIdentifier, error)
	NewToken() (*models.AccessToken, error)
	NewClientIdentifier() (*models.ClientIdentifier, error)
	GetToken() *models.AccessToken
	InitDefaultOauthClientKey()
}

type Auth struct {
	accessToken                     *models.AccessToken
	clientIdentifier                *models.ClientIdentifier
	oauthPublicKey                  *models.TokenKey
	oauthPublicJwk                  *models.Key
	configuration                   *models.Configuration
	tokenExpirationAt               time.Time
	tokenExpirationBuffer           time.Duration
	clientIdentfierExpirationBuffer time.Duration
}

type AgentClaims struct {
	Tenant  string   `json:"ten"`
	Schemas []string `json:"schemas"`
	jwt.RegisteredClaims
}

func NewAgentClaims(clientID, tenant string, expiration time.Duration) AgentClaims {
	return AgentClaims{
		Tenant:  tenant,
		Schemas: []string{"urn:siemens:mindsphere:v1"},
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Issuer:    clientID,
			Subject:   clientID,
			Audience:  []string{"southgate"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}
}

func NewAuth(tokenExpirationBuffer time.Duration, clientIdentifierExpirationBuffer time.Duration) Auther {
	return &Auth{
		tokenExpirationBuffer:           tokenExpirationBuffer,
		clientIdentfierExpirationBuffer: clientIdentifierExpirationBuffer,
	}
}

func (a *Auth) InitDefaultOauthClientKey() {
	pub, err := utils.PublicKeyFromPemFile(SecretPath + "/" + store.PublicKeyFile)

	if err != nil {
		log.Logger.Error(err)
		return
	}
	kty := "RSA"
	kid := "key-1"
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	exp := make([]byte, 3)
	for i := len(exp) - 1; i >= 0; i-- {
		exp[i] = byte(pub.E >> (uint(i) * 8))
	}

	//AQAB
	e := base64.RawURLEncoding.EncodeToString(exp)

	a.oauthPublicJwk = &models.Key{
		E:   &e,
		N:   &n,
		Kty: &kty,
		Kid: &kid,
	}
}

func (a *Auth) SetConfiguration(configuration *models.Configuration) {
	a.configuration = configuration
}

func (a *Auth) SetClientIdentifier(clientIdentifier *models.ClientIdentifier) {
	a.clientIdentifier = clientIdentifier
}

func (a *Auth) SetAccessToken(accessToken *models.AccessToken) {
	a.accessToken = accessToken
}

func (a *Auth) SetOauthPublicKey(oauthPublicKey *models.TokenKey) {
	a.oauthPublicKey = oauthPublicKey
}

func (a *Auth) GetClientIdentifier() *models.ClientIdentifier {
	return a.clientIdentifier
}

func (a *Auth) OnBoard() (*models.ClientIdentifier, error) {

	if a.configuration == nil {
		return nil, errors.New("configuration not found")
	}

	if a.configuration != nil && a.clientIdentifier == nil && a.ConfigurationIsExpired() {
		return nil, errors.New("configuration expired but client identifier not found")
	}

	// register and get client identifier
	if a.clientIdentifier == nil {
		if a.configuration.Content == nil {
			return nil, errors.New("configuration content is nil")
		}
		log.Logger.Info("register client")
		return a.Register()
	}
	// renew client identifier
	if a.clientIdentifier != nil && a.ClientIdentifierIsExpired() {
		log.Logger.Warn("client identifier will expired, renew it")
		return a.NewClientIdentifier()
	}

	return nil, errors.New("client configuration not found or content is nil")
}

func RotateKey() {}

func (a *Auth) CreateClientAssertion() *string {

	serverPublicKey, err := utils.PublicKeyFromPemString(a.oauthPublicKey.Value)
	if err != nil {
		log.Logger.Error(err)
		return nil
	}

	token, err := jwt.Parse(*a.clientIdentifier.RegistrationAccessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return serverPublicKey, nil
	})

	if err != nil {
		log.Logger.Error(err)
		return nil
	}

	if !token.Valid {
		log.Logger.Error("Oauth --> jwt.Parse token is not valid")
		return nil
	}

	tenant := token.Claims.(jwt.MapClaims)["ten"]
	if tenant == nil {
		log.Logger.Error("Oauth --> jwt.Claims tenant is nil")
		return nil
	}

	log.Logger.Info("Oauth --> jwt.Parse successed")

	claims := NewAgentClaims(string(*a.clientIdentifier.ClientID), tenant.(string), time.Minute*30)

	var assertion string

	switch a.configuration.Content.ClientCredentialProfile[0] {
	case "SHARED_SECRET":
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		assertion, err = token.SignedString([]byte(a.clientIdentifier.ClientSecret))
		if err != nil {
			log.Logger.Error(err)
			return nil
		}
	case "RSA_3072":
		key, err := utils.PrivateKeyFromPemFile(SecretPath + "/" + store.PrivateKeyFile)
		if err != nil {
			log.Logger.Error(err)
			return nil
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		assertion, err = token.SignedString(key)
		if err != nil {
			log.Logger.Error(err)
			return nil
		}
	default:
		log.Logger.Error("unsupported client credential profile: " + a.configuration.Content.ClientCredentialProfile[0])
		return nil
	}

	log.Logger.Info("Oatuh --> client jwt generated")

	return &assertion
}

func (a *Auth) AquireToken() (*models.AccessToken, error) {
	if a.oauthPublicKey == nil || a.clientIdentifier == nil {
		return nil, errors.New("client configuration not found or content is nil")
	}

	cs := token_operations.New(
		httptransport.New(ServerHost, AgentApiEndPoint, []string{"https"}),
		strfmt.Default,
	)

	clientAssertion := a.CreateClientAssertion()
	if clientAssertion == nil {
		return nil, errors.New("client assertion not found")
	}

	res, err := cs.PostOauthToken(
		token_operations.NewPostOauthTokenParams().
			WithDefaults().
			WithGrantType(a.clientIdentifier.GrantTypes[0]).
			WithClientAssertionType(ClientAssertionType).
			WithClientAssertion(*clientAssertion),
		token_operations.WithContentType("application/x-www-form-urlencoded"),
	)

	if err != nil {
		log.Logger.Error(err)
		return nil, err
	}

	//set access token expiration time
	a.tokenExpirationAt = time.Now().Add(time.Duration(res.Payload.ExpiresIn) * time.Second)

	return res.Payload, nil
}

func (a *Auth) NewToken() (*models.AccessToken, error) {
	return a.AquireToken()
}

func (a *Auth) Register() (*models.ClientIdentifier, error) {
	var oauthKeys *models.Keys
	switch a.configuration.Content.ClientCredentialProfile[0] {
	case "SHARED_SECRET":
		// TODO create shared secret
		oauthKeys = &models.Keys{}
	case "RSA_3072":
		if a.oauthPublicJwk == nil {
			err := errors.New("oauth client key not found")
			log.Logger.Error(err)
			return nil, err
		}

		// TODO create rsa key
		oauthKeys = &models.Keys{Jwks: &models.Jwks{
			Keys: []*models.Key{a.oauthPublicJwk},
		}}
	default:
		return nil, errors.New("unsupported client credential profile: " + a.configuration.Content.ClientCredentialProfile[0])
	}
	cs := registration_operations.NewClientWithBearerToken(ServerHost, AgentApiEndPoint, "", a.configuration.Content.Iat)

	res, err := cs.PostRegister(
		registration_operations.NewPostRegisterParams().
			WithDefaults().
			WithKeys(oauthKeys),
	)
	if err != nil {
		log.Logger.Error(err)
		return nil, err
	}
	// set client identifier
	a.clientIdentifier = res.Payload
	return res.Payload, nil
}

func (a *Auth) RegisterUpdate() (*models.ClientIdentifier, error) {
	if a.clientIdentifier == nil {
		return nil, errors.New("client identifier not found")
	}

	cs := registration_operations.NewClientWithBearerToken(ServerHost, AgentApiEndPoint, "", *a.clientIdentifier.RegistrationAccessToken)

	clientId := string(*a.clientIdentifier.ClientID)
	var keys *models.RotationKeys
	switch a.configuration.Content.ClientCredentialProfile[0] {
	case "SHARED_SECRET":
		keys = &models.RotationKeys{
			ClientID: clientId,
		}

	case "RSA_3072":
		keys = &models.RotationKeys{
			Jwks: &models.Jwks{Keys: []*models.Key{a.oauthPublicJwk}},
		}
	default:
		return nil, errors.New("unsupported client credential profile: " + a.configuration.Content.ClientCredentialProfile[0])
	}

	res, err := cs.PutRegisterClientID(
		registration_operations.NewPutRegisterClientIDParams().
			WithDefaults().
			WithClientID(clientId).
			WithKeys(keys),
	)

	if err != nil {
		log.Logger.Error(err)
		return nil, err
	}
	//set client identifier
	a.clientIdentifier = res.Payload

	return res.Payload, nil

}

func (a *Auth) NewClientIdentifier() (*models.ClientIdentifier, error) {
	if a.clientIdentifier != nil && a.ClientIdentifierIsExpired() {
		log.Logger.Warn("client identifier will expired, renew it")
		return a.RegisterUpdate()
	}
	return nil, nil
}

func (a *Auth) GetCertificate() (*models.TokenKey, error) {

	cs := token_operations.New(
		httptransport.New(ServerHost, AgentApiEndPoint, []string{"https"}),
		strfmt.Default,
	)
	res, err := cs.GetOauthTokenKey(
		token_operations.NewGetOauthTokenKeyParams().
			WithDefaults(),
	)
	if err != nil {
		log.Logger.Warn("OauthPubKey --> get server pubkey falied")
		return nil, err
	}
	a.oauthPublicKey = res.Payload

	return res.Payload, nil
}

func ValidateToken() {}

func (a *Auth) GetToken() *models.AccessToken {

	if a.TokenIsExpired() {
		log.Logger.Warn("token will expired, please renew token")
		return nil
	}

	return a.accessToken
}

func (a *Auth) ClientIdentifierIsExpired() bool {
	return utils.IsExpired(time.Unix(a.clientIdentifier.ClientSecretExpiresAt, 0), time.Now(), a.clientIdentfierExpirationBuffer)
}

func (a *Auth) ConfigurationIsExpired() bool {
	return utils.IsExpired(time.Time(a.configuration.Expiration), time.Now(), 0)
}

func (a *Auth) TokenIsExpired() bool {
	return utils.IsExpired(a.tokenExpirationAt, time.Now(), a.tokenExpirationBuffer)
}
