package p2p

import (
	"context"
	"net"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/p2p/conn"
)

// AuthenticatedConnection is a [net.Conn] whose remote peer public key has
// been authenticated.
//
// Implementations must delegate all [net.Conn] behavior to the connection
// given to [ConnectionAuthenticator]. In particular, address and deadline
// methods must preserve the underlying socket: the transport keys connection
// tracking on the remote address and bounds the NodeInfo handshake with
// deadlines.
type AuthenticatedConnection interface {
	net.Conn

	// RemotePubKey returns the authenticated remote peer's CometBFT node key.
	// The transport rejects it unless its ID matches the peer's NodeInfo ID and,
	// for outbound connections, the dialed ID.
	RemotePubKey() crypto.PubKey
}

// ConnectionAuthenticator authenticates raw TCP connections during P2P
// upgrade.
//
// Implementations must be safe for concurrent use and must never return a nil
// pointer stored in a non-nil [AuthenticatedConnection] interface. On success,
// each method must return a usable connection. Callers must likewise pass a
// usable, non-nil implementation to [NewMultiplexTransportWithAuthenticator].
//
//go:generate ../scripts/mockery_generate.sh ConnectionAuthenticator
type ConnectionAuthenticator interface {
	// SecureInbound authenticates an inbound connection.
	SecureInbound(context.Context, net.Conn) (AuthenticatedConnection, error)

	// SecureOutbound authenticates an outbound connection to the expected peer ID.
	SecureOutbound(context.Context, net.Conn, ID) (AuthenticatedConnection, error)
}

// Stock STS satisfies AuthenticatedConnection.
var _ AuthenticatedConnection = (*conn.SecretConnection)(nil)
