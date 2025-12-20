package l10n

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Nidal-Bakir/go-todo-backend/internal/utils"
	"github.com/rs/zerolog"

	"github.com/nicksnyder/go-i18n/v2/i18n"

	"golang.org/x/text/language"
)

var (
	bundle                *i18n.Bundle
	locales               = map[string]*Localizer{}
	languageTags          []language.Tag
	languageTagsCanonical []string
)

func SupportedTags() []language.Tag {
	return languageTags
}

func SupportedTagsCanonical() []string {
	return languageTagsCanonical
}

type Localizer struct {
	l      *i18n.Localizer
	logger zerolog.Logger
	tag    language.Tag
}

func InitL10n(ctx context.Context, path string, tags []language.Tag) {
	zlog := *zerolog.Ctx(ctx)

	utils.Assert(len(tags) != 0, "The langs slice can not be empty")
	languageTags = tags

	bundle = i18n.NewBundle(language.English)
	bundle.RegisterUnmarshalFunc("json", json.Unmarshal)

	logEvent := zlog.Info()
	for _, tag := range languageTags {
		canonical := tag.String()
		filePath := fmt.Sprintf(path+"/%s.json", canonical)
		bundle.MustLoadMessageFile(filePath)
		locales[canonical] = &Localizer{l: i18n.NewLocalizer(bundle, canonical), logger: zlog, tag: tag}
		languageTagsCanonical = append(languageTagsCanonical, canonical)
		logEvent.Str(canonical, filePath)
	}
	logEvent.Msg("Localization files loaded")
}

func GetLocalizer(tag language.Tag) *Localizer {
	canonical := tag.String()
	if _, ok := locales[canonical]; !ok {
		l := locales[languageTags[0].String()]
		l.logger.Error().Msgf("Language %s not found, will default to %s", canonical, languageTags[0].String())
		return l
	}
	return locales[canonical]
}

func (l *Localizer) GetLanguageTag() language.Tag {
	return l.tag
}

func (l *Localizer) GetWithId(id string) string {
	return l.localizeMsg(id, nil, nil)
}

func (l *Localizer) GetWithPluralCount(id string, pluralCount int) string {
	return l.localizeMsg(id, nil, pluralCount)
}

func (l *Localizer) GetWithData(id string, data map[string]any) string {
	utils.Assert(data != nil, "The data map can not be nil")
	utils.Assert(len(data) != 0, "The data map should not be empty")

	return l.localizeMsg(id, data, nil)
}

func (l *Localizer) Get(id string, data map[string]string, pluralCount int) string {
	return l.localizeMsg(id, data, pluralCount)
}

func (l *Localizer) localizeMsg(id string, data any, pluralCount any) string {
	cfg := &i18n.LocalizeConfig{
		DefaultMessage: defaultMessage(id),
		TemplateData:   data,
		PluralCount:    pluralCount,
	}

	str, err := l.l.Localize(cfg)
	if err != nil {
		errLog := l.logger.Error().Err(err).Str("id", id)
		if d, ok := data.(map[string]any); ok {
			errLog.Fields(d)
		}
		if pluralCount != nil {
			errLog.Any("pluralCount", pluralCount)
		}
		errLog.Msg("Error getting localized message")

		str = id
	}

	return str
}

func defaultMessage(id string) *i18n.Message {
	return &i18n.Message{
		ID:    id,
		Other: id,
		Zero:  id,
		One:   id,
		Two:   id,
		Few:   id,
		Many:  id,
	}
}
