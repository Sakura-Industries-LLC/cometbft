package core

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/state/mocks"
	"github.com/cometbft/cometbft/types"
)

func TestStatusNilPubKeyReturnsZeroValidatorInfo(t *testing.T) {
	env := newStatusTestEnv(t, true)
	env.PubKey = nil

	status, err := env.Status(nil)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.Empty(t, status.ValidatorInfo.Address)
	assert.Nil(t, status.ValidatorInfo.PubKey)
	assert.Zero(t, status.ValidatorInfo.VotingPower)
	assert.True(t, status.SyncInfo.CatchingUp)
	assert.Equal(t, p2p.DefaultNodeInfo{Moniker: "observer"}, status.NodeInfo)
}

func TestStatusNonNilPubKeyReportsLocalValidator(t *testing.T) {
	priv := types.NewMockPV()
	pubKey, err := priv.GetPubKey()
	require.NoError(t, err)

	env := newStatusTestEnv(t, false)
	env.PubKey = pubKey
	env.StateStore.(*mocks.Store).On("LoadValidators", int64(1)).
		Return(types.NewValidatorSet([]*types.Validator{types.NewValidator(pubKey, 10)}), nil).
		Once()

	status, err := env.Status(nil)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.Equal(t, pubKey.Address().Bytes(), []byte(status.ValidatorInfo.Address))
	assert.Equal(t, pubKey, status.ValidatorInfo.PubKey)
	assert.Equal(t, int64(10), status.ValidatorInfo.VotingPower)
	assert.False(t, status.SyncInfo.CatchingUp)
}

func TestValidatorAtHeightNilPubKey(t *testing.T) {
	env := &Environment{PubKey: nil, StateStore: mocks.NewStore(t)}
	assert.Nil(t, env.validatorAtHeight(1))
}

func TestLocalValidatorInfoNilPubKey(t *testing.T) {
	info := (&Environment{}).localValidatorInfo(7)
	assert.Empty(t, info.Address)
	assert.Nil(t, info.PubKey)
	assert.Equal(t, int64(7), info.VotingPower)
}

func TestLocalValidatorInfoNonNilPubKey(t *testing.T) {
	pubKey := ed25519.GenPrivKey().PubKey()
	info := (&Environment{PubKey: pubKey}).localValidatorInfo(3)
	assert.Equal(t, pubKey.Address().Bytes(), []byte(info.Address))
	assert.Equal(t, pubKey, info.PubKey)
	assert.Equal(t, int64(3), info.VotingPower)
}

func TestValidatorAtHeightMissingSet(t *testing.T) {
	store := mocks.NewStore(t)
	store.On("LoadValidators", int64(1)).Return((*types.ValidatorSet)(nil), errors.New("missing")).Once()
	env := &Environment{PubKey: ed25519.GenPrivKey().PubKey(), StateStore: store}
	assert.Nil(t, env.validatorAtHeight(1))
}

type statusTransport struct {
	info p2p.NodeInfo
}

func (t statusTransport) Listeners() []string { return nil }
func (t statusTransport) IsListening() bool   { return false }
func (t statusTransport) NodeInfo() p2p.NodeInfo {
	return t.info
}

type statusSyncReactor struct {
	wait bool
}

func (r statusSyncReactor) WaitSync() bool { return r.wait }

func newStatusTestEnv(t *testing.T, catchingUp bool) *Environment {
	t.Helper()
	blockStore := &mocks.BlockStore{}
	blockStore.On("LoadBaseMeta").Return((*types.BlockMeta)(nil))
	blockStore.On("Height").Return(int64(0))
	return &Environment{
		BlockStore:       blockStore,
		StateStore:       mocks.NewStore(t),
		ConsensusReactor: statusSyncReactor{wait: catchingUp},
		P2PTransport:     statusTransport{info: p2p.DefaultNodeInfo{Moniker: "observer"}},
	}
}
