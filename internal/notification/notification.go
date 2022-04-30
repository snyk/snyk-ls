package notification

type Event string

var channel = make(chan interface{}, 100)
var stopChannel = make(chan bool, 1)

func CleanChannels() {
	channel = make(chan interface{}, 100)
	stopChannel = make(chan bool, 1)
}

func Send(msg interface{}) {
	channel <- msg
}

func Receive() (payload interface{}, stop bool) {
	select {
	case payload = <-channel:
		return payload, false
	case <-stopChannel:
		return payload, true
	}
}

func CreateListener(callback func(params interface{})) {
	go func() {
		for {
			payload, stop := Receive()
			if stop {
				break
			}
			callback(payload)
		}
	}()
}

func DisposeListener() {
	stopChannel <- true
}
