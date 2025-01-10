package privval

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/crypto/bls12381"
)

func getDialerTestCases(t *testing.T) []dialerTestCase {
	t.Helper()
	tcpAddr := GetFreeLocalhostAddrPort()
	unixFilePath, err := testUnixAddr()
	require.NoError(t, err)
	unixAddr := "unix://" + unixFilePath

	pk, err := bls12381.GenPrivKey()
	require.NoError(t, err)
	return []dialerTestCase{
		{
			addr:   tcpAddr,
			dialer: DialTCPFn(tcpAddr, testTimeoutReadWrite, pk),
		},
		{
			addr:   unixAddr,
			dialer: DialUnixFn(unixFilePath),
		},
	}
}

func TestIsConnTimeoutForFundamentalTimeouts(t *testing.T) {
	// Generate a networking timeout
	tcpAddr := GetFreeLocalhostAddrPort()
	pk, err := bls12381.GenPrivKey()
	require.NoError(t, err)
	dialer := DialTCPFn(tcpAddr, time.Millisecond, pk)
	_, err = dialer()
	require.Error(t, err)
	assert.True(t, IsConnTimeout(err))
}

func TestIsConnTimeoutForWrappedConnTimeouts(t *testing.T) {
	tcpAddr := GetFreeLocalhostAddrPort()
	pk, err := bls12381.GenPrivKey()
	require.NoError(t, err)
	dialer := DialTCPFn(tcpAddr, time.Millisecond, pk)
	_, err = dialer()
	require.Error(t, err)
	err = fmt.Errorf("%v: %w", err, ErrConnectionTimeout)
	assert.True(t, IsConnTimeout(err))
}
