package agent

import (
	"errors"
	"time"

	"github.com/calacaly/mindconnect-go/internal/api/agentmanagement/v3/client/registration_operations"
	"github.com/calacaly/mindconnect-go/internal/api/agentmanagement/v3/client/token_operations"
	"github.com/calacaly/mindconnect-go/internal/api/agentmanagement/v3/models"
	"github.com/calacaly/mindconnect-go/internal/utils"
	"github.com/calacaly/mindconnect-go/pkg/log"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

type Auther interface {
	SetClientIdentifier(clientIdentifier *models.ClientIdentifier)
	SetConfiguration(configuration *models.Configuration)
	SetAccessToken(accessToken *models.AccessToken)
	GetCertificate() (*models.TokenKey, error)
	GetClientIdentifier() *models.ClientIdentifier
	OnBoard() (*models.ClientIdentifier, error)
	AquireToken() error
}

type Auth struct {
	accessToken      *models.AccessToken
	clientIdentifier *models.ClientIdentifier
	oauthKeys        *models.Keys
	oauthPublicKey   *models.TokenKey
	configuration    *models.Configuration
	expirationBuffer time.Duration
}

func NewAuth(expirationBuffer time.Duration) Auther {
	return &Auth{
		expirationBuffer: expirationBuffer,
	}
}

func NewAuthWithStorageLoadConfig(expirationBuffer time.Duration, s StorageClass) Auther {
	auth := &Auth{
		expirationBuffer: expirationBuffer,
	}

	var cfg models.Configuration
	err := s.GetConfig(&cfg)
	if err != nil {
		log.Logger.Warn("Oauth", "load client configuration", err)
	} else {
		auth.SetConfiguration(&cfg)
	}

	var cid models.ClientIdentifier
	err = s.GetConfig(&cid)
	if err != nil {
		log.Logger.Warn("Oauth", "load client identifier", err)
	} else {
		auth.SetClientIdentifier(&cid)
	}

	var at models.AccessToken
	err = s.GetConfig(&at)
	if err != nil {
		log.Logger.Warn("Oauth", "load access token", err)
	} else {

		auth.SetAccessToken(&at)
	}
	return auth
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

func (a *Auth) GetClientIdentifier() *models.ClientIdentifier {
	return a.clientIdentifier
}

func (a *Auth) OnBoard() (*models.ClientIdentifier, error) {
	//TODO check configuration
	// a.checkConfigurationExpiration()

	// register and get client identifier
	if a.clientIdentifier == nil && a.configuration != nil && a.configuration.Content != nil {
		if utils.IsExpired(time.Time(a.configuration.Expiration), time.Now(), a.expirationBuffer) {
			return nil, errors.New("configuration expired")
		}
		switch a.configuration.Content.ClientCredentialProfile[0] {
		case "SHARED_SECRET":
			// TODO create shared secret
			a.oauthKeys = &models.Keys{}
		case "RSA_3072":
			keys := make([]*models.Key, 0, 1)
			kty := "RSA"
			e := "AQAB"
			kid := "key-1"
			n, err := utils.PublicKeyLineFromPemFile(SecretPath + "/" + PublicKeyFile)
			if err != nil {
				log.Logger.Error(err)
				return nil, err
			}
			key := &models.Key{
				Kty: &kty,
				E:   &e,
				Kid: &kid,
				N:   &n,
			}
			keys = append(keys, key)

			// TODO create rsa key
			a.oauthKeys = &models.Keys{Jwks: &models.Jwks{
				Keys: keys,
			}}
		default:
			return nil, errors.New("unsupported client credential profile: " + a.configuration.Content.ClientCredentialProfile[0])
		}
	}
	if a.clientIdentifier == nil {
		log.Logger.Warn("client identifier not found")

		cs := registration_operations.NewClientWithBearerToken(ServerHost, AgentApiEndPoint, "", a.configuration.Content.Iat)

		res, err := cs.PostRegister(
			registration_operations.NewPostRegisterParams().
				WithDefaults().
				WithKeys(a.oauthKeys),
		)
		if err != nil {
			log.Logger.Error(err)
			return nil, err
		}

		return res.Payload, nil
	} else {
		return a.clientIdentifier, errors.New("client configuration not found or content is nil")
	}
}

func PushKey() {}

func RotateKey() {}

func (a *Auth) CreateClientAssertion() {

}

func (a *Auth) AquireToken() error {
	return nil
}

func (a *Auth) RenewSecret() {
	if a.clientIdentifier != nil && utils.IsExpired(time.Unix(a.clientIdentifier.ClientSecretExpiresAt, 0), time.Now(), a.expirationBuffer) {
		// TODO use id and secret to renew secret
	} else {
		// TODO log warning
	}
}

func (a *Auth) RenewToken() {
	if a.accessToken != nil && utils.IsExpired(time.Unix(a.accessToken.ExpiresIn, 0), time.Now(), a.expirationBuffer) {
		// TODO use secret to renew token
	} else {
		// TODO log warning
	}
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

func GetToken() {

}

func SetupAgentCertificate() {}
