package conn

import (
	"net"

	"github.com/cometbft/cometbft/crypto"
)

// AuthenticatedConn is a net.Conn that has completed an authenticated
// handshake and can provide the remote peer's public key.
//
// *SecretConnection satisfies this interface (via its RemotePubKey method).
// External transports (e.g. DNTLS TLS 1.3) can implement it to plug into
// CometBFT's peer infrastructure without using the STS handshake.
type AuthenticatedConn interface {
	net.Conn
	RemotePubKey() crypto.PubKey
}
