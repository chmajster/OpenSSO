# Custom Login UI

OpenSSO can render a centrally managed branded sign-in page without modifying the frontend source code.

## Administration

Administrators with `branding.read` see **Login UI** in the administration navigation. Users with `branding.write` can save or reset the configuration.

The editor provides a live preview and supports:

- enabling or disabling the custom login experience;
- brand name, heading, subheading, notice and footer text;
- logo and background image URLs;
- background, card, text, muted-text, primary, input and border colors;
- login card width and corner radius;
- visibility of the brand name and footer.

Changes are persisted in PostgreSQL and audited as `LOGIN_UI_UPDATED` or `LOGIN_UI_RESET`.

## Security model

Custom login UI deliberately does not accept arbitrary HTML, JavaScript or CSS. All values are structured and validated server-side. Text is rendered by React as text, while media fields accept only absolute `http(s)` URLs or root-relative paths. This avoids turning an administrative branding feature into a persistent script-injection surface.

The public endpoint `GET /api/v1/public/login-ui` exposes only the effective visual configuration needed before authentication. If customization is disabled, it returns the built-in OpenSSO defaults rather than unpublished custom values.

Administrative reads and writes use:

- `GET /api/v1/branding/login-ui` — `branding.read`;
- `PUT /api/v1/branding/login-ui` — `branding.write`;
- `POST /api/v1/branding/login-ui/reset` — `branding.write`.

Mutating requests remain subject to the existing authenticated-session and CSRF protections.

## Media

A logo or background can reference an externally hosted `http(s)` resource or a path served by the same OpenSSO origin, for example:

```text
/branding/company-logo.svg
/branding/login-background.webp
```

OpenSSO does not execute or inject content from these fields as markup.
