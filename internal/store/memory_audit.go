package store

import (
	"context"
	"fmt"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/domain"
)

// --- Audit ---

// AppendAudit seals the record against the tenant's current head and appends
// it. There is no update path and no delete path, in this implementation or
// in Postgres — the absence is the feature (§8.3).
func (m *Memory) AppendAudit(_ context.Context, r domain.AuditRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	prev, ok := m.auditHead[r.TenantID]
	if !ok {
		prev = domain.GenesisHash
	}
	if err := r.Seal(prev); err != nil {
		return err
	}
	m.audit[r.TenantID] = append(m.audit[r.TenantID], r)
	m.auditHead[r.TenantID] = r.Hash
	return nil
}

func (m *Memory) ListAudit(_ context.Context, tenantID string, since time.Time, limit int) ([]domain.AuditRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	records := m.audit[tenantID]
	var out []domain.AuditRecord
	for i := len(records) - 1; i >= 0 && len(out) < limit; i-- {
		if !since.IsZero() && records[i].RecordedAt.Before(since) {
			break
		}
		out = append(out, records[i])
	}
	return out, nil
}

func (m *Memory) LastAuditHash(_ context.Context, tenantID string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if h, ok := m.auditHead[tenantID]; ok {
		return h, nil
	}
	return domain.GenesisHash, nil
}

// VerifyChain recomputes every record's hash and checks it links to its
// predecessor. It reports the first break and stops: everything after a break
// necessarily fails too, and listing all of it buries the one record an
// investigator needs.
func (m *Memory) VerifyChain(_ context.Context, tenantID string) (domain.ChainProof, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	records := m.audit[tenantID]
	proof := domain.ChainProof{
		TenantID:   tenantID,
		Records:    int64(len(records)),
		Intact:     true,
		VerifiedAt: time.Now().UTC(),
	}
	if len(records) == 0 {
		return proof, nil
	}
	proof.From = records[0].RecordedAt
	proof.To = records[len(records)-1].RecordedAt

	prev := domain.GenesisHash
	for _, r := range records {
		if r.PrevHash != prev {
			proof.Intact, proof.BrokenAt = false, r.ID
			proof.Reason = fmt.Sprintf("record links to %s but the previous record hashed to %s", r.PrevHash, prev)
			return proof, nil
		}
		want, err := r.ComputeHash()
		if err != nil {
			proof.Intact, proof.BrokenAt, proof.Reason = false, r.ID, err.Error()
			return proof, nil
		}
		if want != r.Hash {
			proof.Intact, proof.BrokenAt = false, r.ID
			proof.Reason = "record content does not match its stored hash"
			return proof, nil
		}
		prev = r.Hash
	}
	proof.Head = prev
	return proof, nil
}
