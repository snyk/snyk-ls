/*
 * © 2023 Snyk Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package learn

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/erni27/imcache"
	"github.com/pingcap/errors"
	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/types"

	"github.com/snyk/snyk-ls/application/config"
)

type Service interface {
	LearnEndpoint(conf *config.Config) (learnEndpoint string, err error)
	GetLesson(ecosystem string, rule string, cwes []string, cves []string, issueType types.IssueType) (lesson *Lesson, err error)
	GetAllLessons() (lessons []Lesson, err error)
	MaintainCache() func()
}

type Lesson struct {
	LessonId      string   `json:"lessonId"`
	DatePublished string   `json:"datePublished"`
	Author        string   `json:"author"`
	Title         string   `json:"title"`
	Subtitle      string   `json:"subtitle"`
	SeoKeywords   []string `json:"seoKeywords"`
	SeoTitle      string   `json:"seoTitle"`
	Cves          []string `json:"cves"`
	Cwes          []string `json:"cwes"`
	Description   string   `json:"description"`
	Ecosystems    []string `json:"ecosystems"`
	Rules         []string `json:"rules"`
	Slug          string   `json:"slug"`
	Published     bool     `json:"published"`
	Url           string   `json:"url"`
	Source        string   `json:"source"`
	Img           string   `json:"img"`
}

type LessonLookupParams struct {
	Rule      string
	Ecosystem string
	CWEs      []string
	CVEs      []string
}

const cacheExpiry = 24 * time.Hour

var ecosystemAliases = map[string]string{
	"js":             "javascript",
	"ts":             "javascript",
	"npm":            "javascript",
	"yarn":           "javascript",
	"yarn-workspace": "javascript",
	"typescript":     "javascript",
	"javascript":     "javascript",

	"maven":  "java",
	"gradle": "java",
	"java":   "java",

	"pip":    "python",
	"poetry": "python",
	"pipenv": "python",
	"python": "python",

	"nuget":  "csharp",
	"paket":  "csharp",
	"csharp": "csharp",

	"golangdep": "golang",
	"govendor":  "golang",
	"gomodules": "golang",
	"golang":    "golang",

	"composer": "php",
	"php":      "php",

	"rubygems": "ruby",
	"ruby":     "ruby",
	"hex":      "elixir",
	"elixir":   "elixir",
}

type serviceImpl struct {
	logger                  zerolog.Logger
	lessonsByRuleCache      *imcache.Cache[string, []Lesson]
	lessonsByEcosystemCache *imcache.Cache[string, []Lesson]
	conf                    *config.Config
	httpClient              func() *http.Client
	er                      error_reporting.ErrorReporter
}

func New(c *config.Config, httpClientFunc func() *http.Client, er error_reporting.ErrorReporter) Service {
	s := &serviceImpl{
		logger:     c.Logger().With().Str("service", "learn").Logger(),
		conf:       c,
		er:         er,
		httpClient: httpClientFunc,
		lessonsByRuleCache: imcache.New[string, []Lesson](
			imcache.WithDefaultExpirationOption[string, []Lesson](cacheExpiry),
		),
		lessonsByEcosystemCache: imcache.New[string, []Lesson](
			imcache.WithDefaultExpirationOption[string, []Lesson](cacheExpiry),
		),
	}
	return s
}

func (s *serviceImpl) MaintainCache() func() {
	return func() {
		for {
			if s.lessonsByEcosystemCache.Len() == 0 {
				_, err := s.GetAllLessons()
				if err != nil {
					s.er.CaptureError(errors.WithMessage(err, "Error updating lessons cache"))
					return
				}
				time.Sleep(cacheExpiry - 30*time.Second)
			}
			time.Sleep(time.Second)
		}
	}
}

func (s *serviceImpl) GetAllLessons() (lessons []Lesson, err error) {
	logger := s.logger.With().Str("method", "GetAllLessons").Logger()
	learnEndpoint, err := s.LearnEndpoint(s.conf)
	if err != nil {
		return lessons, err
	}

	learnEndpoint = learnEndpoint + "/lessons"
	logger.Debug().Str("LearnEndpoint", learnEndpoint).Msg("learn endpoint")

	resp, err := s.httpClient().Get(learnEndpoint)
	if err != nil {
		logger.Err(err).Msg("failed to retrieve lessons")
		return lessons, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Err(err).Msg("failed to retrieve lessons")
		return lessons, err
	}

	err = json.NewDecoder(resp.Body).Decode(&lessons)
	if err != nil {
		logger.Err(err).Msg("failed to decode response")
		return lessons, err
	}

	s.updateCaches(lessons)
	return lessons, err
}

func (s *serviceImpl) updateCaches(lessons []Lesson) {
	expiration := imcache.WithDefaultExpiration()
	s.lessonsByEcosystemCache.RemoveAll()
	s.lessonsByRuleCache.RemoveAll()

	for _, lesson := range lessons {
		if !lesson.Published {
			continue
		}
		for _, rule := range lesson.Rules {
			lessonsForRule, exists := s.lessonsByRuleCache.Get(rule)
			if !exists {
				lessonsForRule = []Lesson{}
			}
			lessonsForRule = append(lessonsForRule, lesson)
			s.lessonsByRuleCache.Set(lesson.Slug, lessonsForRule, expiration)
		}
		for _, ecosystem := range lesson.Ecosystems {
			lessonsForEcosystem, exists := s.lessonsByEcosystemCache.Get(ecosystem)
			if !exists {
				lessonsForEcosystem = []Lesson{}
			}
			lessonsForEcosystem = append(lessonsForEcosystem, lesson)
			s.lessonsByEcosystemCache.Set(ecosystem, lessonsForEcosystem, expiration)
		}
	}
}

func (s *serviceImpl) GetLesson(ecosystem string, rule string, cwes []string, cves []string, issueType types.IssueType) (lesson *Lesson, err error) {
	logger := s.logger.With().Str("method", "GetLesson").Logger()

	params := s.lessonsLookupParams(ecosystem, rule, cwes, cves, issueType)
	if params == nil {
		return nil, nil
	}

	lessons, exist := s.lessonsByRuleCache.Get(params.Rule)

	if !exist || len(lessons) == 0 {
		logger.Trace().Msgf("no lesson found for rule %v, falling back to ecosystem", params.Rule)
		lessons = s.getLessonsByEcosystem(params)
		if len(lessons) == 0 {
			logger.Trace().Msgf("no lesson found for ecosystem %v, falling back to all", params.Ecosystem)
			for _, v := range s.lessonsByEcosystemCache.GetAll() {
				lessons = append(lessons, v...)
			}
		}
		logger.Trace().Msgf("%d lessons found", len(lessons))
		if len(lessons) == 0 {
			return lesson, err
		}
	}

	lessons = s.filterLessons(lessons, params)

	if len(lessons) >= 1 {
		lesson = &lessons[0]
		if !strings.Contains(lesson.Url, "?loc=ide") {
			lesson.Url += "?loc=ide"
		}
		logger.Trace().Msgf("found lesson %v", lesson)
	}
	return lesson, err
}

func (s *serviceImpl) getLessonsByEcosystem(params *LessonLookupParams) (ecoLessons []Lesson) {
	if params.Ecosystem == "npm" {
		params.Ecosystem = "javascript"
	}
	ecoLessons, _ = s.lessonsByEcosystemCache.Get(ecosystemAliases[strings.ToLower(params.Ecosystem)])
	return
}

func (s *serviceImpl) filterLessons(lessons []Lesson, params *LessonLookupParams) []Lesson {
	logger := s.logger.With().Str("method", "filterLessons").Logger()

	filteredLessons := s.filterForCWEs(lessons, params.CWEs)
	logger.Trace().Msgf("%d lessons found after filtering for CWEs", len(filteredLessons))

	if len(filteredLessons) == 0 && len(params.CVEs) > 0 {
		filteredLessons = s.filterForCVEs(lessons, params.CVEs)
	} else if len(filteredLessons) > 1 && len(params.CVEs) > 0 {
		filteredLessons = s.filterForCVEs(filteredLessons, params.CVEs)
	}
	logger.Trace().Msgf("%d lessons found after filtering for CVEs", len(filteredLessons))
	return filteredLessons
}

func (s *serviceImpl) filterForCWEs(lessons []Lesson, cwes []string) (filteredLessons []Lesson) {
	return s.filterLessonWithComparatorFunc(lessons, cwes, func(lesson Lesson) []string { return lesson.Cwes })
}

func (s *serviceImpl) filterForCVEs(lessons []Lesson, cves []string) (filteredLessons []Lesson) {
	return s.filterLessonWithComparatorFunc(lessons, cves, func(lesson Lesson) []string { return lesson.Cves })
}

func (s *serviceImpl) filterLessonWithComparatorFunc(lessons []Lesson, toCompare []string,
	fieldExtractor func(lesson Lesson) []string) (filteredLessons []Lesson) {
	if len(toCompare) == 0 {
		return lessons
	}
	for _, lesson := range lessons {
		for _, v := range toCompare {
			for _, lessonFieldValue := range fieldExtractor(lesson) {
				// only one needs to match
				if lessonFieldValue == v {
					filteredLessons = append(filteredLessons, lesson)
				}
			}
		}
	}
	return filteredLessons
}

func (s *serviceImpl) lessonsLookupParams(
	ecosystem string,
	rule string,
	cwes []string,
	cves []string,
	issueType types.IssueType,
) (params *LessonLookupParams) {
	// the vscode service only takes the first CWE/CVE
	if len(cwes) > 0 && len(cwes[0]) > 0 {
		cwes = []string{cwes[0]}
	} else {
		cwes = []string{}
	}
	if len(cves) > 0 && len(cves[0]) > 0 {
		cves = []string{cves[0]}
	} else {
		cves = []string{}
	}
	switch issueType {
	case types.DependencyVulnerability:
		params = &LessonLookupParams{
			rule,
			ecosystem,
			cwes,
			cves,
		}
	case types.CodeSecurityVulnerability:
		idParts := strings.Split(rule, "/")
		params = &LessonLookupParams{
			idParts[len(idParts)-1],
			idParts[0],
			cwes,
			cves,
		}
	default:
	}
	return params
}

func (s *serviceImpl) LearnEndpoint(conf *config.Config) (learnEndpoint string, err error) {
	logger := s.logger.With().Str("method", "LearnEndpoint").Logger()
	apiUrl := conf.Engine().GetConfiguration().GetString(configuration.API_URL)
	endpoint, err := url.Parse(apiUrl)
	if err != nil {
		logger.Err(err).Msg("failed to parse Snyk API URL")
		return learnEndpoint, err
	}

	scheme := "https://"
	if strings.HasPrefix(endpoint.Host, "localhost") {
		scheme = "http://"
	}

	learnEndpoint = scheme + endpoint.Host + "/v1/learn"
	logger.Debug().Str("LearnEndpoint", learnEndpoint).Msg("learn endpoint")
	return learnEndpoint, err
}
