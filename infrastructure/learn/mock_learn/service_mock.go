// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/snyk/snyk-ls/infrastructure/learn (interfaces: Service)

// Package mock_learn is a generated GoMock package.
package mock_learn

import (
	"reflect"

	"github.com/golang/mock/gomock"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/learn"
)

// MockService is a mock of Service interface.
type MockService struct {
	ctrl     *gomock.Controller
	recorder *MockServiceMockRecorder
}

// MockServiceMockRecorder is the mock recorder for MockService.
type MockServiceMockRecorder struct {
	mock *MockService
}

// NewMockService creates a new mock instance.
func NewMockService(ctrl *gomock.Controller) *MockService {
	mock := &MockService{ctrl: ctrl}
	mock.recorder = &MockServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockService) EXPECT() *MockServiceMockRecorder {
	return m.recorder
}

// GetAllLessons mocks base method.
func (m *MockService) GetAllLessons() ([]learn.Lesson, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAllLessons")
	ret0, _ := ret[0].([]learn.Lesson)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAllLessons indicates an expected call of GetAllLessons.
func (mr *MockServiceMockRecorder) GetAllLessons() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAllLessons", reflect.TypeOf((*MockService)(nil).GetAllLessons))
}

// GetLesson mocks base method.
func (m *MockService) GetLesson(arg0, arg1 string, arg2, arg3 []string, arg4 snyk.Type) (*learn.Lesson, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetLesson", arg0, arg1, arg2, arg3, arg4)
	ret0, _ := ret[0].(*learn.Lesson)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetLesson indicates an expected call of GetLesson.
func (mr *MockServiceMockRecorder) GetLesson(arg0, arg1, arg2, arg3, arg4 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLesson", reflect.TypeOf((*MockService)(nil).GetLesson), arg0, arg1, arg2, arg3, arg4)
}

// LearnEndpoint mocks base method.
func (m *MockService) LearnEndpoint(arg0 *config.Config) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "LearnEndpoint", arg0)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// LearnEndpoint indicates an expected call of LearnEndpoint.
func (mr *MockServiceMockRecorder) LearnEndpoint(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LearnEndpoint", reflect.TypeOf((*MockService)(nil).LearnEndpoint), arg0)
}

// MaintainCache mocks base method.
func (m *MockService) MaintainCache() func() {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "MaintainCache")
	ret0, _ := ret[0].(func())
	return ret0
}

// MaintainCache indicates an expected call of LearnEndpoint.
func (mr *MockServiceMockRecorder) MaintainCache() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "MaintainCache", reflect.TypeOf((*MockService)(nil).MaintainCache))
}
