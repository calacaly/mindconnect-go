package agent

import (
	"crypto/rsa"
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
	GetCertificate() (*models.TokenKey, error)
	GetClientIdentifier() *models.ClientIdentifier
	OnBoard() (*models.ClientIdentifier, error)
	NewToken() (*models.AccessToken, error)
	NewClientIdentifier() (*models.ClientIdentifier, error)
	GetToken() *models.AccessToken
	WithOptions(...AuthOptions) Auther
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
	publickKey                      *rsa.PublicKey
	privateKey                      *rsa.PrivateKey
}

type AgentClaims struct {
	Tenant  string   `json:"ten"`
	Schemas []string `json:"schemas"`
	jwt.RegisteredClaims
}

// NewAgentClaims generates a JWT payload with the given client id, tenant
// and expiration duration.
//
// The payload will include the standard JWT claims (iss, sub, aud, exp, iat, nbf)
// and the tenant id is included in the "ten" claim.
// The schemas field is always set to "urn:siemens:mindsphere:v1".
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

// NewAuth creates a new instance of the Auth type with the specified token
// expiration buffer and client identifier expiration buffer. It returns an
// Auther interface that can be used to manage authentication processes.
func NewAuth(tokenExpirationBuffer time.Duration, clientIdentifierExpirationBuffer time.Duration) Auther {
	return &Auth{
		tokenExpirationBuffer:           tokenExpirationBuffer,
		clientIdentfierExpirationBuffer: clientIdentifierExpirationBuffer,
	}
}

// NewAuthWithOptions returns an instance of the Auth type using the specified
// token and client identifier expiration buffers, and applies the given options
// to the instance.
func NewAuthWithOptions(tokenExpirationBuffer time.Duration, clientIdentifierExpirationBuffer time.Duration, ops ...AuthOptions) Auther {
	auth := &Auth{
		tokenExpirationBuffer:           tokenExpirationBuffer,
		clientIdentfierExpirationBuffer: clientIdentifierExpirationBuffer,
	}

	for _, opt := range ops {
		opt(auth)
	}
	return auth
}

type AuthOptions func(*Auth)

// WithConfiguration sets the configuration of the agent.
//
// This configuration is used to determine the MindSphere environment and the
// client credential profile.
func WithConfiguration(configuration *models.Configuration) AuthOptions {
	return func(a *Auth) {
		a.configuration = configuration
	}
}

// WithClientIdentifier sets the client identifier that will be used by the
// agent.
func WithClientIdentifier(clientIdentifier *models.ClientIdentifier) AuthOptions {
	return func(a *Auth) {
		a.clientIdentifier = clientIdentifier
	}
}

// WithOauthPublicKey sets the public key of the oauth server.
func WithOauthPublicKey(oauthPublicKey *models.TokenKey) AuthOptions {
	return func(a *Auth) {
		a.oauthPublicKey = oauthPublicKey
	}
}

// WithDefaultOauthClientKey depend on WithOauthPublicKey, please use WithOauthPublicKey first
func WithDefaultOauthClientKey() AuthOptions {
	return func(a *Auth) {
		a.DefaultOauthClientKey()
	}
}

// WithPrivateKey sets the private key for the agent.
// This key is used for signing operations that require a private key.
func WithPrivateKey(privateKey *rsa.PrivateKey) AuthOptions {
	return func(a *Auth) {
		a.privateKey = privateKey
	}
}

// WithPublicKey sets the public key of the agent.
//
// This key is used to create the jwk for the oauth client key. The jwk is
// created by encoding the modulus (n) and exponent (e) of the public key
// in base64url. The jwk is then stored in oauthPublicJwk and can be used
// to register the client at the agent management api.
func WithPublicKey(publicKey *rsa.PublicKey) AuthOptions {
	return func(a *Auth) {
		a.publickKey = publicKey
	}
}

// WithOptions applies the given options to the Auth object.
//
// The options are applied in the order they are given.
//
// WithOptions returns the modified Auth object.
func (a *Auth) WithOptions(opts ...AuthOptions) Auther {
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// DefaultOauthClientKey creates a default jwk key for the oauth client.
//
// This is required for the oauth client registration.
//
// The jwk is created by encoding the modulus (n) and exponent (e) of the
// public key in base64url. The jwk is then stored in oauthPublicJwk and
// can be used to register the client at the agent management api.
//
// The key type is always RSA and the key id is always "key-1".
func (a *Auth) DefaultOauthClientKey() {
	if a.publickKey == nil {
		log.Logger.Warn("Oauth, public key not found")
		return
	}
	pub := a.publickKey
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

// GetClientIdentifier returns the client identifier that has been stored in the
// agent's file system on successful onboarding or registration.
func (a *Auth) GetClientIdentifier() *models.ClientIdentifier {
	return a.clientIdentifier
}

// OnBoard attempts to onboard the client by first checking if the configuration
// and client identifier are available and valid. If the configuration is missing or expired,
// appropriate errors are returned. If a client identifier is not found,
// it attempts to register and obtain a new one. If the existing client identifier is expired,
// it attempts to renew it. Returns the client identifier on success or an error if onboarding fails.
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
		log.Logger.Warn("Oauth, client identifier will expired, renew it")
		return a.NewClientIdentifier()
	}

	return nil, errors.New("client configuration not found or content is nil")
}

// CreateClientAssertion generates a client assertion as a JWT token based on the client identifier.
// It requires the client identifier and the oauth server public key to be set.
// The client assertion is used to authenticate the client with the oauth server in the token endpoint.
// The client assertion is generated according to the client credential profile set in the configuration.
// If the client credential profile is SHARED_SECRET, the client assertion is signed with the client secret.
// If the client credential profile is RSA_3072, the client assertion is signed with the client private key.
// If the client credential profile is not supported, an error is returned.
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
		log.Logger.Error("Oauth", "jwt parse error", "token is not valid")
		return nil
	}

	tenant := token.Claims.(jwt.MapClaims)["ten"]
	if tenant == nil {
		log.Logger.Error("Oauth, jwt parse error", "claims tenant is nil")
		return nil
	}

	log.Logger.Info("Oauth", "jwt parse", "successed")

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
		log.Logger.Error("Oauth", "unsupported client credential profile", a.configuration.Content.ClientCredentialProfile[0])
		return nil
	}

	log.Logger.Info("Oatuh", "create client assertion", "successed")

	return &assertion
}

// AquireToken sends a request to the MindSphere agent management service to obtain
// a new access token using the client assertion.
//
// The client assertion is generated by the CreateClientAssertion method using the
// client identifier and the oauth public key which are stored in the agent's
// file system on successful onboarding.
//
// The obtained access token is stored in the agent and can be accessed using the
// GetToken method.
//
// Returns the access token or an error if the request fails.
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

// NewToken requests a new access token using the client assertion.
//
// The client assertion is generated based on the client identifier and the oauth server
// public key. The obtained access token is stored in the agent and can be accessed using
// the GetToken method.
//
// Returns the access token or an error if the request fails.
func (a *Auth) NewToken() (*models.AccessToken, error) {
	return a.AquireToken()
}

// Register registers the agent with the agent management service.
//
// The agent is registered using the client credential profile specified in the
// configuration. If the client credential profile is not supported, an error is returned.
//
// The obtained client identifier is stored in the agent and can be accessed using
// the GetClientIdentifier method.
//
// Returns the client identifier or an error if the registration fails.
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

// RegisterUpdate sends a request to the MindSphere agent management service to update the client identifier.
//
// The updated client identifier is stored in the agent and can be accessed using
// the GetClientIdentifier method.
//
// Returns the updated client identifier or an error if the registration update fails.
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

// NewClientIdentifier renews the client identifier if it is expired.
//
// Returns the renewed client identifier or an error if the renewal fails.
// If the client identifier is not expired, it returns nil without error.
func (a *Auth) NewClientIdentifier() (*models.ClientIdentifier, error) {
	if a.clientIdentifier != nil && a.ClientIdentifierIsExpired() {
		log.Logger.Warn("Oauth, client identifier will expired, renew it")
		return a.RegisterUpdate()
	}
	return nil, nil
}

// GetCertificate gets the oauth server public key.
//
// Returns the oauth server public key or an error if the request fails.
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
		return nil, err
	}
	a.oauthPublicKey = res.Payload

	return res.Payload, nil
}

// GetToken returns the access token obtained from the agent management service.
//
// If the access token is not found, it returns nil and logs a message.
// If the access token is expired, it returns nil and logs a message.
// Otherwise, it returns the access token.
func (a *Auth) GetToken() *models.AccessToken {
	if a.accessToken == nil {
		log.Logger.Info("Oauth, token not found, please acquire token")
		return nil
	}

	if a.TokenIsExpired() {
		log.Logger.Warn("Oauth, token will expired, please renew token")
		return nil
	}

	return a.accessToken
}

// ClientIdentifierIsExpired determines if the client identifier is expired when
// considering the current time and an additional expiration buffer.
//
// The expiration buffer is a duration subtracted from the client identifier
// expiration time to determine the effective expiration time. This is useful
// for avoiding expiration race conditions due to clock skew.
//
// Returns true if the client identifier is expired, false otherwise.
func (a *Auth) ClientIdentifierIsExpired() bool {
	return utils.IsExpired(time.Unix(a.clientIdentifier.ClientSecretExpiresAt, 0), time.Now(), a.clientIdentfierExpirationBuffer)
}

// ConfigurationIsExpired determines if the agent configuration is expired when
// considering the current time.
//
// Returns true if the configuration is expired, false otherwise.
func (a *Auth) ConfigurationIsExpired() bool {
	return utils.IsExpired(time.Time(a.configuration.Expiration), time.Now(), 0)
}

// TokenIsExpired determines if the access token is expired when
// considering the current time and an additional expiration buffer.
//
// The expiration buffer is a duration subtracted from the token expiration time
// to determine the effective expiration time. This is useful for avoiding
// expiration race conditions due to clock skew.
//
// Returns true if the access token is expired, false otherwise.
func (a *Auth) TokenIsExpired() bool {
	return utils.IsExpired(a.tokenExpirationAt, time.Now(), a.tokenExpirationBuffer)
}
