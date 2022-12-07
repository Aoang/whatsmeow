package gormStore

import (
	"encoding/hex"
	"time"

	"go.mau.fi/whatsmeow/util/keys"
	"gorm.io/gorm"
)

type AppStateMutationMac struct {
	AID      uint64 `gorm:"column:aid;index:idx_app_state_mutation_mac,unique"`
	Name     string `gorm:"index:idx_app_state_mutation_mac,unique"`
	Version  uint64 `gorm:"index:idx_app_state_mutation_mac,unique"`
	IndexMac string `gorm:"index:idx_app_state_mutation_mac,unique"`
	ValueMac string
}

type AppStateSyncKey struct {
	AID         uint64 `gorm:"column:aid;index:idx_app_state_sync_key,unique"`
	KeyID       string `gorm:"index:idx_app_state_sync_key,unique"`
	KeyData     string
	Timestamp   int64
	Fingerprint string
}

type AppStateVersion struct {
	AID     uint64 `gorm:"column:aid;index:idx_app_state_version,unique"`
	Name    string `gorm:"index:idx_app_state_version,unique"`
	Version uint64
	Hash    string
}

type ChatSetting struct {
	AID        uint64 `gorm:"column:aid;index:idx_chat_setting,unique"`
	ChatJID    string `gorm:"column:chat_jid;index:idx_chat_setting,unique"`
	MutedUntil int64
	Pinned     bool
	Archived   bool
}

type Contact struct {
	AID          uint64 `gorm:"column:aid;index:idx_contact,unique"`
	TheirJID     string `gorm:"column:their_jid;index:idx_contact,unique"`
	FirstName    string
	FullName     string
	PushName     string
	BusinessName string
}

type IdentityKey struct {
	AID      uint64 `gorm:"column:aid;index:idx_identity_key,unique"`
	TheirJID string `gorm:"column:their_jid;index:idx_identity_key,unique"`
	Identity string
}

type PreKey struct {
	AID      uint64 `gorm:"column:aid;index:idx_pre_key,unique"`
	KeyID    uint32 `gorm:"index:idx_pre_key,unique"`
	Key      string
	Uploaded bool
}

func (pk PreKey) ToKey() *keys.PreKey {
	bts, err := hex.DecodeString(pk.Key)
	if err != nil || len(bts) != 32 {
		return nil
	}
	return &keys.PreKey{
		KeyPair: *keys.NewKeyPairFromPrivateKey(*(*[32]byte)(bts)),
		KeyID:   pk.KeyID,
	}
}

type SenderKey struct {
	AID       uint64 `gorm:"column:aid;index:idx_sender_key,unique"`
	ChatJID   string `gorm:"column:chat_jid;index:idx_sender_key,unique"`
	SenderID  string `gorm:"index:idx_sender_key,unique"`
	SenderKey string
}

type Session struct {
	AID      uint64 `gorm:"column:aid;index:idx_session,unique"`
	TheirJID string `gorm:"column:their_jid;index:idx_session,unique"`
	Session  string
}

type Account struct {
	ID        uint64         `gorm:"primaryKey"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	JID              string `gorm:"column:jid"`
	RegistrationID   uint32
	NoiseKey         string
	IdentityKey      string
	SignedPreKey     string
	SignedPreKeyID   uint32
	SignedPreKeySig  string
	AdvKey           string
	AdvDetails       string
	AdvAccountSig    string
	AdvAccountSigKey string
	AdvDeviceSig     string
	Platform         string
	BusinessName     string
	PushName         string
	Version          uint64
}

type MessageSecret struct {
	AID       uint64 `gorm:"column:aid;index:idx_message_secret,unique"`
	ChatJID   string `gorm:"column:chat_jid;index:idx_message_secret,unique"`
	SenderID  string `gorm:"index:idx_message_secret,unique"`
	MessageID string `gorm:"index:idx_message_secret,unique"`
	Key       string
}
