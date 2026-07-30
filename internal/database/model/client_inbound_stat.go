package model

import (
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"strings"
)

const ClientInboundStatEmailPrefix = "hmstat"

// ClientInboundStatEmail returns PRIMEVPN's runtime-only Xray stats identity
// for one logical client on one inbound.
//
// The DB/UI/subscription identity remains the logical email. Xray runtime sees
// this generated email so traffic can be attributed per inbound before rolling
// up billable usage to the logical client.
func ClientInboundStatEmail(logicalEmail string, inboundID int) string {
	logicalEmail = strings.ToLower(strings.TrimSpace(logicalEmail))
	if logicalEmail == "" || inboundID <= 0 {
		return ""
	}

	sum := sha256.Sum256([]byte(fmt.Sprintf("%d:%s", inboundID, logicalEmail)))
	encoded := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:]))
	if len(encoded) > 16 {
		encoded = encoded[:16]
	}

	return fmt.Sprintf("%s_%d_%s", ClientInboundStatEmailPrefix, inboundID, encoded)
}

// RuntimeClientEmailForInbound returns the Xray-runtime email for an inbound.
// WireGuard is intentionally kept logical because its peer identity is not a
// regular Xray user email and Phase 1 verified it must not be rewritten.
func RuntimeClientEmailForInbound(inbound *Inbound, logicalEmail string) string {
	if inbound == nil || inbound.Protocol == WireGuard {
		return logicalEmail
	}
	statEmail := ClientInboundStatEmail(logicalEmail, inbound.Id)
	if statEmail == "" {
		return logicalEmail
	}
	return statEmail
}
