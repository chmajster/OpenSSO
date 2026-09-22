# OpenSSO architecture

## 1. Cel i granice systemu

OpenSSO jest self-hosted Identity Providerem i serwerem autoryzacji. Rdzeń jest modularnym monolitem w Go, z PostgreSQL jako źródłem prawdy i Redis jako współdzielonym magazynem stanu krótkotrwałego oraz mechanizmów rate limiting. Panel administracyjny i portal użytkownika są aplikacją React/TypeScript budowaną statycznie i serwowaną przez ten sam publiczny origin co API.

Standardowe endpointy protokołów są rozdzielone od administracyjnego API `/api/v1`. Logika bezpieczeństwa i autoryzacji jest egzekwowana wyłącznie po stronie backendu; frontend nie jest granicą bezpieczeństwa.

## 2. Komponenty

```text
Browser / OIDC client
        |
        v
+---------------------------+
| OpenSSO HTTP server (Go)  |
|---------------------------|
| protocol endpoints        |
| admin/user REST API       |
| auth/session middleware   |
| domain modules            |
| audit + observability     |
+-------------+-------------+
              |
      +-------+-------+
      |               |
      v               v
 PostgreSQL          Redis
 source of truth     shared ephemeral state
```

Docelowe moduły domenowe:

- `auth`: local login, password verification, lockout, bootstrap.
- `users`: lifecycle użytkownika.
- `groups`: grupy i membership.
- `rbac`: role, permissions, assignments.
- `sessions`: sesje przeglądarkowe i ich revocation.
- `applications`: aplikacje oraz klienci OAuth/OIDC.
- `oauth` / `oidc`: authorization server i Identity Provider.
- `keys`: klucze podpisujące i JWKS.
- `audit`: niezmienialny logicznie audit trail operacji bezpieczeństwa.
- `policies`: polityki bezpieczeństwa.
- `directory`, `saml`, `scim`, `federation`, `mfa`, `webauthn`: późniejsze, niezależne granice domenowe.

## 3. Struktura

```text
backend/
  cmd/opensso/
  internal/
    app/
    config/
    database/
    httpx/
    auth/
    users/
    groups/
    rbac/
    sessions/
    applications/
    oauth/
    oidc/
    keys/
    audit/
    policies/
  migrations/
frontend/
  src/
  public/
docs/
  architecture.md
  security.md
  development.md
  deployment.md
```

Moduły nie importują handlerów HTTP innych modułów. Zależności infrastrukturalne są wstrzykiwane przez konstruktor aplikacji. PostgreSQL pozostaje jedynym miejscem trwałego stanu domenowego.

## 4. Model danych

Podstawowe encje:

- `users`, `password_credentials`
- `groups`, `group_memberships`
- `roles`, `permissions`, `role_assignments`
- `sessions`
- `applications`, `oauth_clients`, `oauth_redirect_uris`, `oauth_scopes`, `oauth_consents`
- `authorization_codes`, `refresh_tokens`
- `signing_keys`
- `audit_events`
- `security_policies`

Zasady schematu:

- UUID jako identyfikatory publiczne.
- Foreign keys z jawnie dobraną semantyką kasowania.
- Unique constraints dla nazw/loginów i identyfikatorów protokołów.
- Indeksy na FK, aktywnych tokenach, sesjach i polach filtrowania.
- Sekrety uwierzytelniające przechowywane jako bezpieczne hashe, gdy nie jest potrzebne odzyskanie wartości.
- Pola sekretów wymagające odzyskania są szyfrowane kluczem master key spoza bazy.

## 5. Local authentication

```text
POST /api/v1/auth/login
 -> normalizacja identyfikatora
 -> rate limit
 -> lookup user
 -> weryfikacja stanu konta i lockout
 -> Argon2id verify
 -> opcjonalny rehash parametrów
 -> utworzenie losowej sesji
 -> zapis hash identyfikatora sesji
 -> HttpOnly Secure SameSite cookie
 -> audit LOGIN_SUCCESS / LOGIN_FAILED
```

Sesja przeglądarkowa jest opaque. Cookie zawiera losowy token, a baza przechowuje wyłącznie jego hash. Po logowaniu identyfikator sesji jest zawsze nowy, co eliminuje session fixation.

## 6. Bootstrap pierwszego administratora

Instalacja startuje bez stałych danych logowania. Endpoint bootstrap jest dostępny tylko, gdy w bazie nie istnieje żaden użytkownik. Operacja odbywa się transakcyjnie i tworzy pierwszego administratora wraz z rolą Super Admin. Po utworzeniu pierwszego użytkownika flow bootstrap staje się nieaktywny i kolejne wywołania zwracają konflikt.

## 7. RBAC

Uprawnienia są atomowymi nazwami, np. `users.read`, `users.write`, `applications.manage`, `audit.read`. Role agregują permissions, a assignment może wskazywać użytkownika. Każdy endpoint administracyjny deklaruje wymagane permission. `Super Admin` posiada pełny zestaw uprawnień.

## 8. OIDC/OAuth flow

### Authorization Code + PKCE

```text
Client
 -> GET /oauth2/authorize
 -> exact redirect_uri match
 -> client/grant/scope validation
 -> authenticated browser session
 -> state/nonce retained as request parameters
 -> one-time authorization code
 -> redirect to client

Client
 -> POST /oauth2/token
 -> client authentication when required
 -> authorization code lookup
 -> expiry + one-time check
 -> redirect_uri equality
 -> PKCE S256 verification
 -> atomic code consumption
 -> access token + ID token + refresh token
```

Authorization code ma bardzo krótki TTL i jest konsumowany atomowo. Public client wymaga PKCE S256. Wildcard redirect URI nie jest wspierany.

### Refresh token rotation

Refresh token jest opaque, kryptograficznie losowy, a baza przechowuje hash. Każde poprawne użycie unieważnia token i wydaje nowy token w tej samej rodzinie. Ponowne użycie wcześniej zużytego tokenu oznacza reuse detection i unieważnia aktywną rodzinę.

### Access/ID tokens

JWT są podpisywane biblioteką kryptograficzną obsługującą JWK/JWS. Domyślnym algorytmem jest RS256 dla szerokiej interoperacyjności. Nagłówek zawiera `kid`. `alg=none` nie jest akceptowany.

ID token zawiera minimalny zestaw OIDC claims oraz tylko claims dozwolone dla klienta i scope.

## 9. Discovery i JWKS

Publiczne endpointy:

- `/.well-known/openid-configuration`
- `/.well-known/oauth-authorization-server`
- `/.well-known/jwks.json`

Metadata jest generowane na podstawie skonfigurowanego issuer i faktycznie obsługiwanych funkcji; nie reklamuje grantów ani metod nieuwdrożonych.

JWKS publikuje aktywny klucz oraz poprzednie klucze pozostawione na okres nie krótszy niż maksymalny czas życia tokenu.

## 10. Logout i revocation

- Logout użytkownika unieważnia sesję przeglądarkową.
- `/oauth2/revoke` obsługuje refresh tokens i, jeśli stosowane, server-side reference tokens.
- Admin może unieważnić pojedynczą sesję, wszystkie sesje użytkownika lub globalnie sesje.
- Revocation jest sprawdzana po stronie serwera dla stanowych artefaktów.

## 11. Audit

Każda istotna operacja bezpieczeństwa tworzy `audit_events` z:

- timestamp,
- actor,
- target,
- event,
- result,
- IP,
- user-agent,
- request/correlation ID,
- bezpiecznymi metadata.

Nigdy nie trafiają tam hasła, pełne tokeny, recovery codes, client secrets ani prywatne klucze.

## 12. Threat model

### Chronione aktywa

- credentials użytkowników,
- sesje,
- authorization codes,
- refresh tokens,
- signing keys,
- client credentials,
- role/permission assignments,
- konfiguracja issuer i redirect URIs,
- audit trail.

### Główne zagrożenia i kontrolki

| Zagrożenie | Kontrolki |
|---|---|
| Credential stuffing / brute force | rate limiting w Redis, lockout, audit |
| Session fixation / theft | rotacja przy loginie, opaque token, HttpOnly/Secure/SameSite, revocation |
| CSRF | SameSite + CSRF protection dla state-changing cookie-auth API |
| XSS | React escaping, CSP, brak inline scriptów, walidacja danych |
| OAuth redirect bypass | exact URI match po znormalizowanym, zarejestrowanym URI |
| Authorization code replay | jednorazowy code, atomic consume, krótki TTL |
| PKCE downgrade | public clients wymagają S256, plain niedozwolone |
| Refresh replay | rotation + family reuse detection |
| JWT algorithm confusion | jawna lista dozwolonych algorytmów, klucz wg kid |
| Privilege escalation / IDOR | permission checks w backendzie i resource ownership checks |
| SQL injection | parametryzowane zapytania pgx |
| SSRF | allow-list/protocol validation w przyszłych konektorach directory/federation |
| Secret leakage | hash lub envelope encryption, redaction logów |
| Key compromise | rotacja, rozdzielenie public/private material, brak logowania key material |
| Race conditions | transakcje i warunkowe UPDATE dla code/token consumption |

## 13. Security headers

Publiczny serwer ustawia co najmniej:

- Content-Security-Policy,
- X-Content-Type-Options: nosniff,
- Referrer-Policy,
- frame-ancestors przez CSP,
- HSTS w trybie produkcyjnym pod HTTPS.

CORS jest domyślnie wyłączony dla administracyjnego API poza jawnie skonfigurowanymi originami.

## 14. Skalowanie poziome

Instancje backendu są bezstanowe poza lokalnym cache bez znaczenia autorytatywnego. Wspólny stan znajduje się w PostgreSQL i Redis. Dzięki temu wiele replik może obsługiwać logowanie i protokoły za wspólnym load balancerem.

Operacje jednorazowe, takie jak zużycie authorization code oraz rotacja refresh tokenu, są wykonywane transakcyjnie w PostgreSQL. Rate limits są współdzielone przez Redis.

## 15. Health i observability

- `/health/live`: proces działa.
- `/health/ready`: aktywne sprawdzenie PostgreSQL i Redis.
- structured JSON logs z request ID.
- metryki Prometheus dla HTTP, logowań i wyników auth.
- brak PII/secrets w labelach metryk.

## 16. Migracje i deployment

Migracje są wersjonowane i wykonywane kontrolowanie przed uruchomieniem ruchu aplikacyjnego. Deployment nie wymaga ręcznego tworzenia tabel. Docker Compose uruchamia OpenSSO, PostgreSQL i Redis, a readiness blokuje gotowość do czasu dostępności wymaganych zależności.

## 17. Frontend

Frontend komunikuje się tylko z `/api/v1`, nie odtwarza logiki autoryzacyjnej. Każdy ekran posiada loading, empty, error i success state. Operacje destrukcyjne wymagają potwierdzenia.

Pierwszy zakres UI obejmuje wyłącznie działające ekrany: setup, login, dashboard, users, groups, applications, sessions, audit i ustawienia bezpieczeństwa dostępne w bieżącym etapie. Funkcje z późniejszych etapów nie są eksponowane, dopóki backend nie jest gotowy.
