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

package testutil

import (
	"sync"

	"github.com/creachadair/jrpc2"
)

type JsonRPCRecorder struct {
	callbacks     []jrpc2.Request
	notifications []jrpc2.Request
	mutex         sync.Mutex
}

func (r *JsonRPCRecorder) Record(request jrpc2.Request) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if request.IsNotification() {
		r.notifications = append(r.notifications, request)
	} else {
		r.callbacks = append(r.callbacks, request)
	}
}

func (r *JsonRPCRecorder) Notifications() []jrpc2.Request {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.notifications
}

func (r *JsonRPCRecorder) Callbacks() []jrpc2.Request {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.callbacks
}

func (r *JsonRPCRecorder) FindNotificationsByMethod(method string) []jrpc2.Request {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	var found []jrpc2.Request
	for _, notification := range r.notifications {
		if notification.Method() == method {
			found = append(found, notification)
		}
	}
	return found
}

func (r *JsonRPCRecorder) FindCallbacksByMethod(method string) []jrpc2.Request {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	var found []jrpc2.Request
	for _, callback := range r.callbacks {
		if callback.Method() == method {
			found = append(found, callback)
		}
	}
	return found
}

func (r *JsonRPCRecorder) ClearCallbacks() {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.callbacks = []jrpc2.Request{}
}

func (r *JsonRPCRecorder) ClearNotifications() {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.notifications = []jrpc2.Request{}
}
