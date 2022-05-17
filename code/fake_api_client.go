package code

const (
	SastEnabledOperation = "sastEnabled"
)

type FakeApiClient struct {
	Calls       map[string][][]interface{}
	CodeEnabled bool
}

func (f *FakeApiClient) addCall(params []interface{}, op string) {
	mutex.Lock()
	defer mutex.Unlock()
	if f.Calls == nil {
		f.Calls = make(map[string][][]interface{})
	}
	calls := f.Calls[op]
	var opParams []interface{}
	for p := range params {
		opParams = append(opParams, params[p])
	}
	f.Calls[op] = append(calls, opParams)
}

func (f *FakeApiClient) GetCallParams(callNo int, op string) []interface{} {
	mutex.Lock()
	defer mutex.Unlock()
	calls := f.Calls[op]
	if calls == nil {
		return nil
	}
	params := calls[callNo]
	if params == nil {
		return nil
	}
	return params
}

func (f *FakeApiClient) Clear() {
	f.Calls = map[string][][]interface{}{}
}

func (f *FakeApiClient) GetAllCalls(op string) [][]interface{} {
	mutex.Lock()
	defer mutex.Unlock()
	calls := f.Calls[op]
	if calls == nil {
		return nil
	}
	return calls
}

func (f *FakeApiClient) SastEnabled() (sastEnabled bool, localCodeEngineEnabled bool, reportFalsePositivesEnabled bool, err error) {
	f.addCall([]interface{}{}, SastEnabledOperation)
	return f.CodeEnabled, false, false, nil
}
