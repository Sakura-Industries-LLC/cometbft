package node

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cfg "github.com/cometbft/cometbft/config"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/p2p"
	p2pmocks "github.com/cometbft/cometbft/p2p/mocks"
)

// TestNewNodeWithContextAndAuthenticatorNil pins fail-closed construction
// without an authenticator.
func TestNewNodeWithContextAndAuthenticatorNil(t *testing.T) {
	n, err := NewNodeWithContextAndAuthenticator(
		context.Background(),
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
	)
	require.ErrorIs(t, err, p2p.ErrNilAuthenticator)
	assert.Nil(t, n)
}

// TestNewNodeWithContextAndAuthenticatorLibP2P pins rejection for the
// unsupported experimental libp2p transport.
func TestNewNodeWithContextAndAuthenticatorLibP2P(t *testing.T) {
	config := cfg.DefaultConfig()
	config.P2P.LibP2PConfig.Enabled = true

	n, err := NewNodeWithContextAndAuthenticator(
		context.Background(),
		config,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		log.TestingLogger(),
		p2pmocks.NewConnectionAuthenticator(t),
	)
	require.ErrorIs(t, err, p2p.ErrUnsupportedTransport)
	assert.Nil(t, n)
}
