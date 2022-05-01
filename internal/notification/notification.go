package notification

type Event string

var channel = make(chan interface{}, 100)

func Send(msg interface{}) {
	channel <- msg
}

func Receive() interface{} {
	return <-channel
}

func CreateListener(callback func(params interface{})) {
	go func() {
		for {
			callback(Receive())
		}
	}()
}
