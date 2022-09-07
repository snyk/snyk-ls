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
