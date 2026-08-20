package p2p

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/p2p/conn"
)

// stsAuthenticator performs real stock STS through the injected authenticator
// contract.
type stsAuthenticator struct {
	// privKey is the local STS identity.
	privKey crypto.PrivKey
}

// SecureInbound performs stock STS for an accepted connection.
func (a *stsAuthenticator) SecureInbound(_ context.Context, c net.Conn) (AuthenticatedConnection, error) {
	return upgradeSecretConn(c, defaultHandshakeTimeout, a.privKey)
}

// SecureOutbound performs stock STS for a dialed connection.
func (a *stsAuthenticator) SecureOutbound(_ context.Context, c net.Conn, _ ID) (AuthenticatedConnection, error) {
	return upgradeSecretConn(c, defaultHandshakeTimeout, a.privKey)
}

// stubAuthConn is a non-Secret authenticated connection used to prove peer ID
// derivation.
type stubAuthConn struct {
	// Conn supplies the connection behavior not exercised by the ID test.
	net.Conn
	// pubKey is the authenticated remote key.
	pubKey crypto.PubKey
}

// RemotePubKey returns the fixture's authenticated remote key.
func (c stubAuthConn) RemotePubKey() crypto.PubKey { return c.pubKey }

// blockingAuthenticator ignores context cancellation and blocks on socket I/O
// so the transport-level deadline can be tested.
type blockingAuthenticator struct{}

// SecureInbound blocks on a read until the transport's socket deadline fires.
func (blockingAuthenticator) SecureInbound(_ context.Context, c net.Conn) (AuthenticatedConnection, error) {
	var b [1]byte
	_, err := c.Read(b[:])
	return nil, err
}

// SecureOutbound blocks on a read until the transport's socket deadline fires.
func (blockingAuthenticator) SecureOutbound(_ context.Context, c net.Conn, _ ID) (AuthenticatedConnection, error) {
	var b [1]byte
	_, err := c.Read(b[:])
	return nil, err
}

// TestNewMultiplexTransportWithAuthenticatorNil pins the required dependency.
func TestNewMultiplexTransportWithAuthenticatorNil(t *testing.T) {
	mt, err := NewMultiplexTransportWithAuthenticator(
		emptyNodeInfo(),
		NodeKey{PrivKey: ed25519.GenPrivKey()},
		conn.DefaultMConnConfig(),
		nil,
	)
	require.ErrorIs(t, err, ErrNilAuthenticator)
	assert.Nil(t, mt)
}

// TestMultiplexTransportAuthenticatorInboundOutbound proves the injected
// adapter handles both connection directions.
func TestMultiplexTransportAuthenticatorInboundOutbound(t *testing.T) {
	listenerAuth := &stsAuthenticator{privKey: ed25519.GenPrivKey()}
	listenerID := PubKeyToID(listenerAuth.privKey.PubKey())
	mt, err := NewMultiplexTransportWithAuthenticator(
		testNodeInfo(listenerID, "listener"),
		NodeKey{PrivKey: listenerAuth.privKey},
		conn.DefaultMConnConfig(),
		listenerAuth,
	)
	require.NoError(t, err)

	addr, err := NewNetAddressString(IDAddressString(listenerID, "127.0.0.1:0"))
	require.NoError(t, err)
	require.NoError(t, mt.Listen(*addr))
	t.Cleanup(func() { _ = mt.Close() })

	dialerAuth := &stsAuthenticator{privKey: ed25519.GenPrivKey()}
	dialerID := PubKeyToID(dialerAuth.privKey.PubKey())
	dialer, err := NewMultiplexTransportWithAuthenticator(
		testNodeInfo(dialerID, "dialer"),
		NodeKey{PrivKey: dialerAuth.privKey},
		conn.DefaultMConnConfig(),
		dialerAuth,
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = dialer.Close() })

	dialAddr := NewNetAddress(mt.nodeKey.ID(), mt.listener.Addr())
	errc := make(chan error, 1)
	go func() {
		p, err := dialer.Dial(*dialAddr, peerConfig{})
		if err != nil {
			errc <- err
			return
		}
		defer func() { _ = p.CloseConn() }()
		if p.NodeInfo().ID() != listenerID {
			errc <- fmt.Errorf("peer ID mismatch: have %s, want %s", p.NodeInfo().ID(), listenerID)
			return
		}
		close(errc)
	}()

	p, err := mt.Accept(peerConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.CloseConn() })
	assert.Equal(t, dialerID, p.NodeInfo().ID())
	require.NoError(t, <-errc)
}

// TestMultiplexTransportAuthenticatorHandshakeDeadline proves the transport
// bounds socket I/O even when an authenticator ignores its context.
func TestMultiplexTransportAuthenticatorHandshakeDeadline(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})

	mt := makeMultiplexTransport(
		emptyNodeInfo(),
		NodeKey{PrivKey: ed25519.GenPrivKey()},
		conn.DefaultMConnConfig(),
		blockingAuthenticator{},
	)
	mt.handshakeTimeout = 25 * time.Millisecond

	done := make(chan error, 1)
	go func() {
		_, err := mt.authenticateConn(server, nil)
		done <- err
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		var netErr net.Error
		require.ErrorAs(t, err, &netErr)
		assert.True(t, netErr.Timeout())
	case <-time.After(time.Second):
		t.Fatal("injected authentication did not honor the transport handshake deadline")
	}
}

// TestMultiplexTransportAuthenticatorPostAuthChecks proves Comet retains its
// dialed-ID and NodeInfo compatibility admission checks.
func TestMultiplexTransportAuthenticatorPostAuthChecks(t *testing.T) {
	t.Run("dialed ID mismatch is an auth failure", func(t *testing.T) {
		mt := testSetupAuthenticatedTransport(t, "listener")
		pv := ed25519.GenPrivKey()
		dialer, err := NewMultiplexTransportWithAuthenticator(
			testNodeInfo(PubKeyToID(pv.PubKey()), "dialer"),
			NodeKey{PrivKey: pv},
			conn.DefaultMConnConfig(),
			&stsAuthenticator{privKey: pv},
		)
		require.NoError(t, err)
		t.Cleanup(func() { _ = dialer.Close() })

		wrongID := PubKeyToID(ed25519.GenPrivKey().PubKey())
		addr := NewNetAddress(wrongID, mt.listener.Addr())
		_, err = dialer.Dial(*addr, peerConfig{})
		require.Error(t, err)
		rej, ok := err.(ErrRejected)
		require.True(t, ok)
		assert.True(t, rej.IsAuthFailure())
	})

	t.Run("incompatible NodeInfo is rejected after auth", func(t *testing.T) {
		mt := testSetupAuthenticatedTransport(t, "listener")
		pv := ed25519.GenPrivKey()
		dialer, err := NewMultiplexTransportWithAuthenticator(
			testNodeInfoWithNetwork(PubKeyToID(pv.PubKey()), "dialer", "incompatible-network"),
			NodeKey{PrivKey: pv},
			conn.DefaultMConnConfig(),
			&stsAuthenticator{privKey: pv},
		)
		require.NoError(t, err)
		t.Cleanup(func() { _ = dialer.Close() })

		errc := make(chan error, 1)
		go func() {
			addr := NewNetAddress(mt.nodeKey.ID(), mt.listener.Addr())
			_, err := dialer.Dial(*addr, peerConfig{})
			errc <- err
		}()

		_, err = mt.Accept(peerConfig{})
		require.Error(t, err)
		rej, ok := err.(ErrRejected)
		require.True(t, ok)
		assert.True(t, rej.IsIncompatible())
		<-errc
	})
}

// TestPeerConnIDFromAuthenticatedConnection proves peer identity no longer
// depends on the concrete stock SecretConnection type.
func TestPeerConnIDFromAuthenticatedConnection(t *testing.T) {
	pubKey := ed25519.GenPrivKey().PubKey()
	pc := newPeerConn(false, false, stubAuthConn{
		Conn:   &testTransportConn{},
		pubKey: pubKey,
	}, nil)
	assert.Equal(t, PubKeyToID(pubKey), pc.ID())
}

// testSetupAuthenticatedTransport starts one listener using real STS through
// the injected authenticator contract.
func testSetupAuthenticatedTransport(t *testing.T, name string) *MultiplexTransport {
	t.Helper()
	pv := ed25519.GenPrivKey()
	id := PubKeyToID(pv.PubKey())
	mt, err := NewMultiplexTransportWithAuthenticator(
		testNodeInfo(id, name),
		NodeKey{PrivKey: pv},
		conn.DefaultMConnConfig(),
		&stsAuthenticator{privKey: pv},
	)
	require.NoError(t, err)

	addr, err := NewNetAddressString(IDAddressString(id, "127.0.0.1:0"))
	require.NoError(t, err)
	require.NoError(t, mt.Listen(*addr))
	t.Cleanup(func() { _ = mt.Close() })
	return mt
}
