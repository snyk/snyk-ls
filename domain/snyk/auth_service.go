/*
 * © 2022 Snyk Limited All rights reserved.
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

import "context"

type AuthenticationService interface {
	// Authenticate attempts to authenticate the user, and sends a notification to the client when successful
	Authenticate(ctx context.Context) (string, error)

	Provider() AuthenticationProvider

	// UpdateToken stores the token in the configuration, and sends a $/snyk.hasAuthenticated notification to the
	// client if sendNotification is true
	UpdateToken(newToken string, sendNotification bool)

	Logout(ctx context.Context)

	// IsAuthenticated returns true if the token is verified
	IsAuthenticated() (bool, error)
}
