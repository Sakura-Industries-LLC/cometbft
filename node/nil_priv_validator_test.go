package node

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cfg "github.com/cometbft/cometbft/config"
	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/privval"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/proxy"
	sm "github.com/cometbft/cometbft/state"
	"github.com/cometbft/cometbft/types"
)

const observerPersistentPeer = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@127.0.0.1:26656"

func TestNodeConstructsNilPrivValidatorObserver(t *testing.T) {
	config := newObserverNodeTestConfig(t)
	require.NoError(t, os.Remove(config.PrivValidatorKeyFile()))
	require.NoError(t, os.Remove(config.PrivValidatorStateFile()))

	n := mustNewNode(t, config, nil)
	t.Cleanup(func() { require.NoError(t, n.Close()) })

	assert.Nil(t, n.PrivValidator(), "nil signer must stay nil")
	assert.False(t, onlyValidatorIsUs(mustLoadState(t, n), nil), "empty local address is not the sole validator")
	assert.True(t, n.ConsensusReactor().WaitSync(), "observer must remain a block-syncing full node")
	assert.NoFileExists(t, config.PrivValidatorKeyFile())
	assert.NoFileExists(t, config.PrivValidatorStateFile())
}

func TestNodeConfigureRPCNilPrivValidator(t *testing.T) {
	config := newObserverNodeTestConfig(t)
	n := mustNewNode(t, config, nil)
	t.Cleanup(func() { require.NoError(t, n.Close()) })

	env, err := n.ConfigureRPC()
	require.NoError(t, err)
	require.NotNil(t, env)
	assert.Nil(t, env.PubKey)

	status, err := env.Status(nil)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.Empty(t, status.ValidatorInfo.Address)
	assert.Nil(t, status.ValidatorInfo.PubKey)
	assert.Zero(t, status.ValidatorInfo.VotingPower)
	assert.True(t, status.SyncInfo.CatchingUp)
}

func TestNodeNewNodeGetPubKeyError(t *testing.T) {
	config := newObserverNodeTestConfig(t)
	_, err := NewNode(
		config,
		failingPubKeyPV{err: errors.New("pubkey unavailable")},
		mustNodeKey(t, config),
		proxy.DefaultClientCreator(config.ProxyApp, config.ABCI, config.DBDir()),
		DefaultGenesisDocProviderFunc(config),
		cfg.DefaultDBProvider,
		DefaultMetricsProvider(config.Instrumentation),
		log.TestingLogger(),
	)
	require.Error(t, err)
	assert.ErrorContains(t, err, "can't get pubkey")
}

func TestNodeConfigureRPCGetPubKeyError(t *testing.T) {
	config := newObserverNodeTestConfig(t)
	n := mustNewNode(t, config, privval.LoadOrGenFilePV(config.PrivValidatorKeyFile(), config.PrivValidatorStateFile()))
	t.Cleanup(func() { require.NoError(t, n.Close()) })

	n.privValidator = failingPubKeyPV{err: errors.New("pubkey unavailable")}
	_, err := n.ConfigureRPC()
	require.Error(t, err)
	assert.ErrorContains(t, err, "can't get pubkey")

	n.privValidator = failingPubKeyPV{}
	_, err = n.ConfigureRPC()
	require.Error(t, err)
	assert.ErrorContains(t, err, "can't get pubkey")
}

func newObserverNodeTestConfig(t *testing.T) *cfg.Config {
	t.Helper()
	config := newNodeTestConfig(t, "node_nil_priv_validator_test")
	t.Cleanup(func() { os.RemoveAll(config.RootDir) })
	config.P2P.PersistentPeers = observerPersistentPeer
	return config
}

func mustNewNode(t *testing.T, config *cfg.Config, privValidator types.PrivValidator) *Node {
	t.Helper()
	n, err := NewNode(
		config,
		privValidator,
		mustNodeKey(t, config),
		proxy.DefaultClientCreator(config.ProxyApp, config.ABCI, config.DBDir()),
		DefaultGenesisDocProviderFunc(config),
		cfg.DefaultDBProvider,
		DefaultMetricsProvider(config.Instrumentation),
		log.TestingLogger(),
	)
	require.NoError(t, err)
	return n
}

func mustNodeKey(t *testing.T, config *cfg.Config) *p2p.NodeKey {
	t.Helper()
	nodeKey, err := p2p.LoadOrGenNodeKey(config.NodeKeyFile())
	require.NoError(t, err)
	return nodeKey
}

func mustLoadState(t *testing.T, n *Node) sm.State {
	t.Helper()
	state, err := n.stateStore.Load()
	require.NoError(t, err)
	return state
}

type failingPubKeyPV struct {
	key crypto.PubKey
	err error
}

func (pv failingPubKeyPV) GetPubKey() (crypto.PubKey, error) {
	return pv.key, pv.err
}

func (failingPubKeyPV) SignVote(string, *cmtproto.Vote) error { return nil }

func (failingPubKeyPV) SignProposal(string, *cmtproto.Proposal) error { return nil }

var _ types.PrivValidator = failingPubKeyPV{}

func TestOnlyValidatorIsUsEmptyAddress(t *testing.T) {
	oneVal, _, _ := state(1, 1)
	assert.False(t, onlyValidatorIsUs(oneVal, nil))
	assert.False(t, onlyValidatorIsUs(oneVal, crypto.Address{}))

	empty := oneVal
	empty.Validators = types.NewValidatorSet(nil)
	assert.False(t, onlyValidatorIsUs(empty, nil))
	assert.False(t, onlyValidatorIsUs(empty, crypto.Address{}))
}
