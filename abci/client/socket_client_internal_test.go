package abcicli

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/abci/types"
)

// A response that lands after flushQueue (client shutdown) must not call Done
// a second time on a ReqRes that flushQueue already released.
func TestFlushQueueThenDidRecvResponse(t *testing.T) {
	cli := NewSocketClient("127.0.0.1:0", false).(*socketClient)

	reqres := NewReqRes(types.ToRequestEcho("hi"))
	cli.reqSent.PushBack(reqres)

	cli.flushQueue()

	res := types.ToResponseEcho("hi")
	var err error
	require.NotPanics(t, func() {
		err = cli.didRecvResponse(res)
	})
	require.ErrorAs(t, err, &ErrUnexpectedResponse{})
}
