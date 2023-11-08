/*
 * © 2022-2023 Snyk Limited
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

package oss

import (
	"time"

	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/internal/lsp"
)

type identifiers struct {
	CWE  []string `json:"CWE,omitempty"`
	GHSA []string `json:"GHSA,omitempty"`
	CVE  []string `json:"CVE,omitempty"`
}

type reference struct {
	Title string  `json:"title"`
	Url   lsp.Uri `json:"url"`
}

type ossIssue struct {
	Id             string        `json:"id"`
	Name           string        `json:"name"`
	Title          string        `json:"title"`
	Severity       string        `json:"severity"`
	LineNumber     int           `json:"lineNumber"`
	Description    string        `json:"description"`
	References     []reference   `json:"references,omitempty"`
	Version        string        `json:"version"`
	PackageManager string        `json:"packageManager"`
	PackageName    string        `json:"packageName"`
	From           []string      `json:"from"`
	Identifiers    identifiers   `json:"identifiers,omitempty"`
	FixedIn        []string      `json:"fixedIn,omitempty"`
	UpgradePath    []any         `json:"upgradePath,omitempty"`
	IsUpgradable   bool          `json:"isUpgradable,omitempty"`
	CVSSv3         string        `json:"CVSSv3,omitempty"`
	CvssScore      float64       `json:"cvssScore,omitempty"`
	Exploit        string        `json:"exploit,omitempty"`
	IsPatchable    bool          `json:"isPatchable"`
	License        string        `json:"license,omitempty"`
	Language       string        `json:"language,omitempty"`
	matchingIssues []*ossIssue   `json:"-"`
	lesson         *learn.Lesson `json:"-"`
}

type licensesPolicy struct {
	Severities struct {
	} `json:"severities"`
	OrgLicenseRules struct {
		GPL20 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"GPL-2.0"`
		GPL30 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"GPL-3.0"`
		LGPL20 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"LGPL-2.0"`
		LGPL30 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"LGPL-3.0"`
		EPL10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"EPL-1.0"`
		EPL20 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"EPL-2.0"`
		CPOL102 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CPOL-1.02"`
		MPL10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"MPL-1.0"`
		MPL11 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"MPL-1.1"`
		MPL20 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"MPL-2.0"`
		MPL20NoCopyleftException struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"MPL-2.0-no-copyleft-exception"`
		AGPL30 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"AGPL-3.0"`
		AGPL10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"AGPL-1.0"`
		MSRL struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"MS-RL"`
		GPL20WithClasspathException struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"GPL-2.0-with-classpath-exception"`
		APSL10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"APSL-1.0"`
		APSL11 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"APSL-1.1"`
		APSL12 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"APSL-1.2"`
		APSL20 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"APSL-2.0"`
		CPAL10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CPAL-1.0"`
		EUPL10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"EUPL-1.0"`
		EUPL11 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"EUPL-1.1"`
		OSL30 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"OSL-3.0"`
		Artistic10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"Artistic-1.0"`
		Artistic10Perl struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"Artistic-1.0-Perl"`
		Artistic10Cl8 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"Artistic-1.0-cl8"`
		Artistic20 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"Artistic-2.0"`
		RPSL10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"RPSL-1.0"`
		RPL11 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"RPL-1.1"`
		RPL15 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"RPL-1.5"`
		CCBYNC10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-NC-1.0"`
		CCBYNC20 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-NC-2.0"`
		CCBYNC25 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-NC-2.5"`
		CCBYNC30 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-NC-3.0"`
		CCBYNC40 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-NC-4.0"`
		CCBYNCND10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-NC-ND-1.0"`
		CCBYNCND20 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-NC-ND-2.0"`
		CCBYNCND25 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-NC-ND-2.5"`
		CCBYNCND30 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-NC-ND-3.0"`
		CCBYNCND40 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-NC-ND-4.0"`
		CCBYNCSA10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-NC-SA-1.0"`
		CCBYNCSA20 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-NC-SA-2.0"`
		CCBYNCSA25 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-NC-SA-2.5"`
		CCBYNCSA30 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-NC-SA-3.0"`
		CCBYNCSA40 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-NC-SA-4.0"`
		CCBYND10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-ND-1.0"`
		CCBYND20 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-ND-2.0"`
		CCBYND25 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-ND-2.5"`
		CCBYND30 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-ND-3.0"`
		CCBYND40 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-ND-4.0"`
		CCBYSA10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-SA-1.0"`
		CCBYSA40 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-SA-4.0"`
		CCBYSA30 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-SA-3.0"`
		CCBYSA25 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-SA-2.5"`
		CCBYSA20 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CC-BY-SA-2.0"`
		GPL10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"GPL-1.0"`
		LGPL21 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"LGPL-2.1"`
		CDDL10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CDDL-1.0"`
		CDDL11 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CDDL-1.1"`
		OSL10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"OSL-1.0"`
		OSL11 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"OSL-1.1"`
		OSL20 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"OSL-2.0"`
		OSL21 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"OSL-2.1"`
		CPL10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CPL-1.0"`
		Sleepycat struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"Sleepycat"`
		AFL11 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"AFL-1.1"`
		AFL12 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"AFL-1.2"`
		AFL20 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"AFL-2.0"`
		AFL21 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"AFL-2.1"`
		AFL30 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"AFL-3.0"`
		OCLC20 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"OCLC-2.0"`
		LGPLLR struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"LGPLLR"`
		QPL10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"QPL-1.0"`
		SISSL struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"SISSL"`
		SISSL12 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"SISSL-1.2"`
		Watcom10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"Watcom-1.0"`
		CECILL10 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CECILL-1.0"`
		CECILL11 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CECILL-1.1"`
		CECILL20 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CECILL-2.0"`
		CECILL21 struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CECILL-2.1"`
		CECILLB struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CECILL-B"`
		CECILLC struct {
			LicenseType  string `json:"licenseType"`
			Severity     string `json:"severity"`
			Instructions string `json:"instructions"`
		} `json:"CECILL-C"`
	} `json:"orgLicenseRules"`
}

type ignoreSettings struct {
	AdminOnly                  bool `json:"adminOnly"`
	ReasonRequired             bool `json:"reasonRequired"`
	DisregardFilesystemIgnores bool `json:"disregardFilesystemIgnores"`
}

type Insights struct {
	TriageAdvice any `json:"triageAdvice"`
}

type remediation struct {
	Unresolved []struct {
		CVSSv3           string      `json:"CVSSv3,omitempty"`
		AlternativeIds   []any       `json:"alternativeIds,omitempty"`
		CreationTime     time.Time   `json:"creationTime"`
		Credit           []string    `json:"credit,omitempty"`
		CvssScore        float64     `json:"cvssScore,omitempty"`
		Description      string      `json:"description"`
		DisclosureTime   time.Time   `json:"disclosureTime,omitempty"`
		Exploit          string      `json:"exploit,omitempty"`
		Functions        []any       `json:"functions,omitempty"`
		FixedIn          []string    `json:"fixedIn,omitempty"`
		Id               string      `json:"id"`
		Identifiers      identifiers `json:"identifiers,omitempty"`
		Language         string      `json:"language"`
		Malicious        bool        `json:"malicious,omitempty"`
		ModificationTime time.Time   `json:"modificationTime,omitempty"`
		ModuleName       string      `json:"moduleName,omitempty"`
		PackageManager   string      `json:"packageManager"`
		PackageName      string      `json:"packageName"`
		Patches          []any       `json:"patches,omitempty"`
		Proprietary      bool        `json:"proprietary,omitempty"`
		PublicationTime  time.Time   `json:"publicationTime"`
		References       []reference `json:"references,omitempty"`
		Severity         string      `json:"severity"`
		SocialTrendAlert bool        `json:"socialTrendAlert,omitempty"`
		Title            string      `json:"title"`
		Insights         Insights    `json:"insights,omitempty"`
		FunctionsNew     []any       `json:"functions_new,omitempty"`
		Semver           struct {
			Vulnerable []string `json:"vulnerable"`
		} `json:"semver"`
		MavenModuleName struct {
			GroupId    string `json:"groupId"`
			ArtifactId string `json:"artifactId"`
		} `json:"mavenModuleName,omitempty"`
		From                 []string `json:"from"`
		UpgradePath          []any    `json:"upgradePath"`
		IsUpgradable         bool     `json:"isUpgradable"`
		IsPatchable          bool     `json:"isPatchable"`
		IsPinnable           bool     `json:"isPinnable"`
		IsRuntime            bool     `json:"isRuntime"`
		Name                 string   `json:"name"`
		Version              string   `json:"version"`
		SeverityWithCritical string   `json:"severityWithCritical"`
		License              string   `json:"license,omitempty"`
		Type                 string   `json:"type,omitempty"`
	} `json:"unresolved"`
	Upgrade struct {
	} `json:"upgrade"`
	Patch struct {
	} `json:"patch"`
	Ignore struct {
	} `json:"ignore"`
	Pin struct {
	} `json:"pin"`
}

type scanResult struct {
	Vulnerabilities   []ossIssue     `json:"vulnerabilities"`
	Ok                bool           `json:"ok"`
	DependencyCount   int            `json:"dependencyCount"`
	Policy            string         `json:"policy"`
	IsPrivate         bool           `json:"isPrivate"`
	LicensesPolicy    licensesPolicy `json:"licensesPolicy"`
	PackageManager    string         `json:"packageManager"`
	IgnoreSettings    ignoreSettings `json:"ignoreSettings"`
	Summary           string         `json:"summary"`
	FilesystemPolicy  bool           `json:"filesystemPolicy"`
	UniqueCount       int            `json:"uniqueCount"`
	ProjectName       string         `json:"projectName"`
	FoundProjectCount int            `json:"foundProjectCount"`
	DisplayTargetFile string         `json:"displayTargetFile"`
	Path              string         `json:"path"`
	Remediation       remediation    `json:"remediation,omitempty"`
	Filtered          struct {
		Ignore []any `json:"ignore"`
		Patch  []any `json:"patch"`
	} `json:"filtered,omitempty"`
}
