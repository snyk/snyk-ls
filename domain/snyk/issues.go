/*
 * Copyright 2022 Snyk Ltd.
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

package snyk

import (
	"fmt"
	"net/url"
)

type Reference struct {
	Title string
	Url   *url.URL
}

// Issue models a problem, vulnerability, or situation within your code that requires your attention
type Issue struct {
	// ID uniquely identifies the issue, it is intended to be human-readable
	ID        string
	Severity  Severity
	IssueType Type
	// Range identifies the location of this issue in its source of origin (e.g. line & character start & end)
	Range Range
	// Message is a human-readable description of the issue
	Message string
	// todo [jc] this contains a formatted longest message for hovers, this needs to be pushed up and rendered in presentation. [bd] shouldn't the content and formatting be decided by the product?
	FormattedMessage string
	// AffectedFilePath is the file path to the file where the issue was found
	AffectedFilePath string
	// Product is the Snyk product, e.g. Snyk Open Source
	Product Product // todo: can we avoid it, if it's part of a scanner interface already?
	// References deliver additional information
	References []Reference
	// IssueDescriptionURL contains a Uri to display more information
	IssueDescriptionURL *url.URL
	// CodeActions can contain workspace edits or commands to be executed
	CodeActions []CodeAction
	// Commands that can be executed
	Commands []Command
}

func NewIssue(id string, severity Severity, issueType Type, r Range, message string, formattedMessage string, affectedFilePath string, product Product, references []Reference, issueDescriptionUrl *url.URL, codeActions []CodeAction, commands []Command) Issue {
	return Issue{
		ID:                  id,
		Severity:            severity,
		IssueType:           issueType,
		Range:               r,
		Message:             message,
		FormattedMessage:    formattedMessage,
		AffectedFilePath:    affectedFilePath,
		Product:             product,
		References:          references,
		IssueDescriptionURL: issueDescriptionUrl,
		CodeActions:         codeActions,
		Commands:            commands,
	}
}

func (i Issue) String() string {
	return fmt.Sprintf("%s, ID: %s, Range: %s", i.AffectedFilePath, i.ID, i.Range)
}

type Severity int8

// Type of issue, these will typically match 1o1 to Snyk product lines but are not necessarily coupled to those.
type Type int8

const (
	Critical Severity = iota
	High
	Medium
	Low
)

const (
	PackageHealth Type = iota
	CodeQualityIssue
	CodeSecurityVulnerability
	LicenceIssue
	DependencyVulnerability
	InfrastructureIssue
	ContainerVulnerability
)
