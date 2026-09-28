package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

type loginUISettings struct {
	Enabled              bool   `json:"enabled"`
	BrandName            string `json:"brand_name"`
	Heading              string `json:"heading"`
	Subheading           string `json:"subheading"`
	LogoURL              string `json:"logo_url"`
	BackgroundImageURL   string `json:"background_image_url"`
	BackgroundColor      string `json:"background_color"`
	CardColor            string `json:"card_color"`
	TextColor            string `json:"text_color"`
	MutedTextColor       string `json:"muted_text_color"`
	PrimaryColor         string `json:"primary_color"`
	InputBackgroundColor string `json:"input_background_color"`
	BorderColor          string `json:"border_color"`
	CardRadius           int    `json:"card_radius"`
	CardWidth            int    `json:"card_width"`
	NoticeText           string `json:"notice_text"`
	FooterText           string `json:"footer_text"`
	ShowBrandName        bool   `json:"show_brand_name"`
	ShowFooter           bool   `json:"show_footer"`
}

var loginUIColorPattern = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

func defaultLoginUISettings() loginUISettings {
	return loginUISettings{
		Enabled:              false,
		BrandName:            "OpenSSO",
		Heading:              "Sign in",
		Subheading:           "Use your OpenSSO account.",
		BackgroundColor:      "#0b1020",
		CardColor:            "#11192d",
		TextColor:            "#e8edf5",
		MutedTextColor:       "#9db0ca",
		PrimaryColor:         "#5b7cfa",
		InputBackgroundColor: "#0d1526",
		BorderColor:          "#223150",
		CardRadius:           16,
		CardWidth:            460,
		ShowBrandName:        true,
		ShowFooter:           false,
	}
}

func (s *Server) loadLoginUISettings(ctx context.Context) (loginUISettings, error) {
	var out loginUISettings
	err := s.db.QueryRow(ctx, `
		SELECT enabled,brand_name,heading,subheading,logo_url,background_image_url,
		       background_color,card_color,text_color,muted_text_color,primary_color,
		       input_background_color,border_color,card_radius,card_width,notice_text,
		       footer_text,show_brand_name,show_footer
		FROM login_ui_settings WHERE id=1
	`).Scan(
		&out.Enabled, &out.BrandName, &out.Heading, &out.Subheading, &out.LogoURL, &out.BackgroundImageURL,
		&out.BackgroundColor, &out.CardColor, &out.TextColor, &out.MutedTextColor, &out.PrimaryColor,
		&out.InputBackgroundColor, &out.BorderColor, &out.CardRadius, &out.CardWidth, &out.NoticeText,
		&out.FooterText, &out.ShowBrandName, &out.ShowFooter,
	)
	return out, err
}

func normalizeLoginUISettings(in loginUISettings) (loginUISettings, error) {
	in.BrandName = strings.TrimSpace(in.BrandName)
	in.Heading = strings.TrimSpace(in.Heading)
	in.Subheading = strings.TrimSpace(in.Subheading)
	in.LogoURL = strings.TrimSpace(in.LogoURL)
	in.BackgroundImageURL = strings.TrimSpace(in.BackgroundImageURL)
	in.NoticeText = strings.TrimSpace(in.NoticeText)
	in.FooterText = strings.TrimSpace(in.FooterText)

	if in.BrandName == "" || utf8.RuneCountInString(in.BrandName) > 100 {
		return in, fmt.Errorf("brand_name must contain 1-100 characters")
	}
	if in.Heading == "" || utf8.RuneCountInString(in.Heading) > 120 {
		return in, fmt.Errorf("heading must contain 1-120 characters")
	}
	if utf8.RuneCountInString(in.Subheading) > 240 || utf8.RuneCountInString(in.NoticeText) > 500 || utf8.RuneCountInString(in.FooterText) > 240 {
		return in, fmt.Errorf("login UI text exceeds allowed length")
	}
	if in.CardRadius < 0 || in.CardRadius > 48 {
		return in, fmt.Errorf("card_radius must be between 0 and 48")
	}
	if in.CardWidth < 320 || in.CardWidth > 720 {
		return in, fmt.Errorf("card_width must be between 320 and 720")
	}
	if len(in.LogoURL) > 2048 || len(in.BackgroundImageURL) > 2048 {
		return in, fmt.Errorf("login UI media URL exceeds 2048 bytes")
	}
	for name, value := range map[string]string{
		"background_color":       in.BackgroundColor,
		"card_color":             in.CardColor,
		"text_color":             in.TextColor,
		"muted_text_color":       in.MutedTextColor,
		"primary_color":          in.PrimaryColor,
		"input_background_color": in.InputBackgroundColor,
		"border_color":           in.BorderColor,
	} {
		if !loginUIColorPattern.MatchString(value) {
			return in, fmt.Errorf("%s must be a six-digit hexadecimal color", name)
		}
	}
	if err := validateLoginUIMediaURL(in.LogoURL); err != nil {
		return in, fmt.Errorf("logo_url: %w", err)
	}
	if err := validateLoginUIMediaURL(in.BackgroundImageURL); err != nil {
		return in, fmt.Errorf("background_image_url: %w", err)
	}
	return in, nil
}

func validateLoginUIMediaURL(raw string) error {
	if raw == "" {
		return nil
	}
	if strings.ContainsAny(raw, "\"'\\\r\n\t") {
		return fmt.Errorf("contains characters unsafe for a CSS/image URL")
	}
	u, err := url.ParseRequestURI(raw)
	if err != nil || u.Fragment != "" || u.User != nil {
		return fmt.Errorf("must be an absolute http(s) URL or a root-relative path")
	}
	if strings.HasPrefix(raw, "/") {
		if strings.HasPrefix(raw, "//") || u.Scheme != "" || u.Host != "" || !strings.HasPrefix(u.Path, "/") {
			return fmt.Errorf("must be an absolute http(s) URL or a root-relative path")
		}
		return nil
	}
	if u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("must be an absolute http(s) URL or a root-relative path")
	}
	return nil
}

func (s *Server) publicLoginUI(w http.ResponseWriter, r *http.Request) {
	out, err := s.loadLoginUISettings(r.Context())
	if err != nil {
		problem(w, http.StatusInternalServerError, "database error")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if !out.Enabled {
		out = defaultLoginUISettings()
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) adminLoginUI(w http.ResponseWriter, r *http.Request) {
	out, err := s.loadLoginUISettings(r.Context())
	if err != nil {
		problem(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) updateLoginUI(w http.ResponseWriter, r *http.Request) {
	var in loginUISettings
	if decodeJSON(w, r, &in) != nil {
		return
	}
	in, err := normalizeLoginUISettings(in)
	if err != nil {
		problem(w, http.StatusBadRequest, err.Error())
		return
	}
	p := r.Context().Value(principalKey).(principal)
	_, err = s.db.Exec(r.Context(), `
		UPDATE login_ui_settings SET
		  enabled=$1,brand_name=$2,heading=$3,subheading=$4,logo_url=$5,background_image_url=$6,
		  background_color=$7,card_color=$8,text_color=$9,muted_text_color=$10,primary_color=$11,
		  input_background_color=$12,border_color=$13,card_radius=$14,card_width=$15,notice_text=$16,
		  footer_text=$17,show_brand_name=$18,show_footer=$19,updated_at=now(),updated_by=$20
		WHERE id=1
	`, in.Enabled, in.BrandName, in.Heading, in.Subheading, in.LogoURL, in.BackgroundImageURL,
		in.BackgroundColor, in.CardColor, in.TextColor, in.MutedTextColor, in.PrimaryColor,
		in.InputBackgroundColor, in.BorderColor, in.CardRadius, in.CardWidth, in.NoticeText,
		in.FooterText, in.ShowBrandName, in.ShowFooter, p.UserID)
	if err != nil {
		problem(w, http.StatusInternalServerError, "database error")
		return
	}
	_ = s.audit(r.Context(), &p.UserID, "LOGIN_UI_UPDATED", "login_ui", "1", "success", r)
	writeJSON(w, http.StatusOK, in)
}

func (s *Server) resetLoginUI(w http.ResponseWriter, r *http.Request) {
	in := defaultLoginUISettings()
	p := r.Context().Value(principalKey).(principal)
	_, err := s.db.Exec(r.Context(), `
		UPDATE login_ui_settings SET
		  enabled=$1,brand_name=$2,heading=$3,subheading=$4,logo_url='',background_image_url='',
		  background_color=$5,card_color=$6,text_color=$7,muted_text_color=$8,primary_color=$9,
		  input_background_color=$10,border_color=$11,card_radius=$12,card_width=$13,notice_text='',
		  footer_text='',show_brand_name=$14,show_footer=$15,updated_at=now(),updated_by=$16
		WHERE id=1
	`, in.Enabled, in.BrandName, in.Heading, in.Subheading, in.BackgroundColor, in.CardColor,
		in.TextColor, in.MutedTextColor, in.PrimaryColor, in.InputBackgroundColor, in.BorderColor,
		in.CardRadius, in.CardWidth, in.ShowBrandName, in.ShowFooter, p.UserID)
	if err != nil {
		problem(w, http.StatusInternalServerError, "database error")
		return
	}
	_ = s.audit(r.Context(), &p.UserID, "LOGIN_UI_RESET", "login_ui", "1", "success", r)
	writeJSON(w, http.StatusOK, in)
}
