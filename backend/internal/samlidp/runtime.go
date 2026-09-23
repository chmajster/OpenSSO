package samlidp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/chmajster/OpenSSO/backend/internal/config"
	"github.com/zitadel/saml/pkg/provider"
	"github.com/zitadel/saml/pkg/provider/signature"
	"github.com/zitadel/saml/pkg/provider/serviceprovider"
	samlxml "github.com/zitadel/saml/pkg/provider/xml"
	"github.com/zitadel/saml/pkg/provider/xml/md"
)

const (
	rsaSHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	sha256    = "http://www.w3.org/2001/04/xmlenc#sha256"
)

type Runtime struct {
	cfg          config.Config
	storage      *Storage
	certificates *CertificateManager
	idp          *provider.IdentityProvider
	handler      http.Handler
	issuer       string
}

func NewRuntime(cfg config.Config, storage *Storage, certificates *CertificateManager) (*Runtime, error) {
	issuer := strings.TrimRight(cfg.PublicURL, "/") + "/saml"
	idpConfig := &provider.IdentityProviderConfig{
		MetadataIDPConfig: &provider.MetadataIDPConfig{
			ValidUntil:    24 * time.Hour,
			CacheDuration: "PT1H",
		},
		SignatureAlgorithm: rsaSHA256,
		DigestAlgorithm:    sha256,
		// A service provider may declare AuthnRequestsSigned=true in its
		// metadata. OpenSSO can additionally force this per registration.
		WantAuthRequestsSigned: "false",
		Endpoints: &provider.EndpointConfig{
			Certificate:  endpoint("certificate"),
			Callback:     endpoint("callback"),
			SingleSignOn: endpoint("sso"),
			SingleLogOut: endpoint("slo"),
			Attribute:    endpoint("attribute"),
		},
	}
	idp, err := provider.NewIdentityProvider(provider.NewEndpoint("metadata"), idpConfig, storage)
	if err != nil {
		return nil, err
	}
	rt := &Runtime{
		cfg: cfg, storage: storage, certificates: certificates,
		idp: idp, issuer: issuer,
	}
	rt.handler = rt.buildHandler()
	return rt, nil
}

func endpoint(path string) *provider.Endpoint {
	value := provider.NewEndpoint(path)
	return &value
}

func (r *Runtime) Handler() http.Handler {
	return r.handler
}

func (r *Runtime) EntityID() string {
	return r.issuer + "/metadata"
}

func (r *Runtime) CallbackURL(requestID string) string {
	return r.issuer + "/callback?id=" + requestID
}

func (r *Runtime) FinalizeAuthRequest(ctx context.Context, requestID, userID string) (string, error) {
	return r.storage.FinalizeAuthRequest(ctx, requestID, userID)
}

func (r *Runtime) RotateCertificate(ctx context.Context) error {
	_, err := r.certificates.Rotate(ctx)
	return err
}

func (r *Runtime) CertificateMetadata(ctx context.Context) ([]map[string]any, error) {
	return r.certificates.Metadata(ctx)
}

func (r *Runtime) buildHandler() http.Handler {
	routes := map[string]http.HandlerFunc{}
	for _, route := range r.idp.GetRoutes() {
		switch route.Endpoint {
		case "/certificate", "/callback", "/sso":
			routes[route.Endpoint] = route.HandleFunc
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if len(req.URL.RawQuery) > 128*1024 {
			http.Error(w, "SAML request query is too large", http.StatusRequestEntityTooLarge)
			return
		}
		if relayState := req.URL.Query().Get("RelayState"); len(relayState) > 1024 {
			http.Error(w, "SAML RelayState is too large", http.StatusBadRequest)
			return
		}
		path := strings.TrimPrefix(req.URL.Path, "/saml")
		if path == "/metadata" {
			if req.Method != http.MethodGet {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			r.metadata(w, req)
			return
		}
		handler, ok := routes[path]
		if !ok {
			http.NotFound(w, req)
			return
		}
		if path == "/sso" && req.Method != http.MethodGet {
			// Initial production profile accepts Redirect-bound AuthnRequest
			// and emits POST-bound responses.
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if path == "/callback" && req.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if req.Method == http.MethodPost {
			req.Body = http.MaxBytesReader(w, req.Body, 1024*1024)
		}
		ctx := provider.ContextWithIssuer(req.Context(), r.issuer)
		handler(w, req.WithContext(ctx))
	})
}

func (r *Runtime) metadata(w http.ResponseWriter, req *http.Request) {
	ctx := provider.ContextWithIssuer(req.Context(), r.issuer)
	idpMetadata, _, err := r.idp.GetMetadata(ctx)
	if err != nil {
		http.Error(w, "failed to build SAML metadata", http.StatusInternalServerError)
		return
	}
	// Do not advertise protocol surfaces OpenSSO does not expose yet.
	idpMetadata.SingleLogoutService = nil
	idpMetadata.NameIDFormat = []string{
		"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
	}

	entity := &md.EntityDescriptorType{
		EntityID:         md.EntityIDType(r.EntityID()),
		Id:               provider.NewID(),
		ValidUntil:       time.Now().UTC().Add(24 * time.Hour).Format(provider.DefaultTimeFormat),
		CacheDuration:    "PT1H",
		IDPSSODescriptor: idpMetadata,
	}
	certAndKey, err := r.certificates.Active(ctx)
	if err != nil {
		http.Error(w, "failed to load SAML signing certificate", http.StatusInternalServerError)
		return
	}
	signer, err := signature.GetSigner(certAndKey.Certificate, certAndKey.Key, rsaSHA256)
	if err != nil {
		http.Error(w, "failed to initialize SAML metadata signer", http.StatusInternalServerError)
		return
	}
	entity.Signature, err = signature.Create(signer, entity)
	if err != nil {
		http.Error(w, "failed to sign SAML metadata", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/samlmetadata+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	if err := samlxml.WriteXMLMarshalled(w, entity); err != nil {
		http.Error(w, fmt.Errorf("failed to write SAML metadata: %w", err).Error(), http.StatusInternalServerError)
	}
}

func ValidateServiceProviderMetadata(metadataXML string) (entityID string, err error) {
	if len(metadataXML) == 0 || len(metadataXML) > 1024*1024 {
		return "", errors.New("SAML SP metadata must be between 1 byte and 1 MiB")
	}
	sp, err := serviceProviderForValidation(metadataXML)
	if err != nil {
		return "", err
	}
	if sp.Metadata == nil || sp.Metadata.SPSSODescriptor == nil {
		return "", errors.New("metadata does not contain SPSSODescriptor")
	}
	entityID = strings.TrimSpace(sp.GetEntityID())
	if entityID == "" || len(entityID) > 2048 {
		return "", errors.New("invalid SAML SP entityID")
	}
	hasPOSTACS := false
	for _, acs := range sp.Metadata.SPSSODescriptor.AssertionConsumerService {
		if acs.Binding == provider.PostBinding && strings.TrimSpace(acs.Location) != "" {
			hasPOSTACS = true
			break
		}
	}
	if !hasPOSTACS {
		return "", errors.New("SAML SP metadata must contain an HTTP-POST AssertionConsumerService")
	}
	return entityID, nil
}

func serviceProviderForValidation(metadataXML string) (*serviceprovider.ServiceProvider, error) {
	return serviceprovider.NewServiceProvider(
		"metadata-validation",
		&serviceprovider.Config{Metadata: []byte(metadataXML)},
		func(string) string { return "" },
	)
}
