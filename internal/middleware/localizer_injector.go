package middleware

import (
	"errors"
	"net/http"
	"slices"

	"github.com/Nidal-Bakir/go-todo-backend/internal/l10n"
	"github.com/Nidal-Bakir/go-todo-backend/internal/utils/resutils"
	"github.com/rs/zerolog"
	"golang.org/x/text/language"
)

func LocalizerInjector(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		var tag language.Tag
		var err error

		if lang := r.FormValue("Accept-Language"); lang != "" {
			tag, err = language.Parse(lang)
		} else {
			lang = r.Header.Get("Accept-Language")
			tags, _, parseErr := language.ParseAcceptLanguage(lang)
			err = parseErr
			if err == nil {
				supportedTagsCanonical := l10n.SupportedTagsCanonical()
				for _, t := range tags {
					if slices.Contains(supportedTagsCanonical, t.String()) {
						tag = t
						break
					}
				}
			}
		}

		if err != nil {
			resutils.WriteError(ctx, w, r, http.StatusBadRequest, errors.New("missing or invalid Accept-Language in the request header or in Query Parameter"))
			return
		}

		ctx = l10n.ContextWithLocalizer(ctx, l10n.GetLocalizer(tag))
		ctx = zerolog.Ctx(ctx).With().Str("lang", tag.String()).Logger().WithContext(ctx)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
