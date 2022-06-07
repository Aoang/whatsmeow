package gormStore

import (
	"time"

	"go.mau.fi/whatsmeow/types"
	"gorm.io/gorm"
)

type AppStateMutationMac struct {
	JID      types.JID `gorm:"index:idx_app_state_mutation_mac,unique"`
	Name     string    `gorm:"index:idx_app_state_mutation_mac,unique"`
	Version  uint64    `gorm:"index:idx_app_state_mutation_mac,unique"`
	IndexMac string    `gorm:"index:idx_app_state_mutation_mac,unique"`
	ValueMac string
}

type AppStateSyncKey struct {
	JID         types.JID `gorm:"index:idx_app_state_sync_key,unique"`
	KeyID       string    `gorm:"index:idx_app_state_sync_key,unique"`
	Timestamp   int64
	Fingerprint string
}

type AppStateVersion struct {
	JID     types.JID `gorm:"index:idx_app_state_version,unique"`
	Name    string    `gorm:"index:idx_app_state_version,unique"`
	Version uint64
	Hash    string
}
type ChatSetting struct {
	OurJID     types.JID `gorm:"index:idx_chat_setting,unique"`
	ChatJID    types.JID `gorm:"index:idx_chat_setting,unique"`
	MutedUntil int64
	Pinned     bool
	Archived   bool
}

type Contact struct {
	OurJID       types.JID `gorm:"index:idx_contact,unique"`
	TheirJID     types.JID `gorm:"index:idx_contact,unique"`
	FirstName    string
	FullName     string
	PushName     string
	BusinessName string
}

type Device struct {
	JID              types.JID `gorm:"index:idx_device_jid,unique"`
	RegistrationID   uint32
	NoiseKey         string
	IdentityKey      string
	SignedPreKey     string
	SignedPreKeyID   uint32
	SignedPreKeySig  string
	AdvKey           string
	AdvDetails       string
	AdvAccountSig    string
	AdvDeviceSig     string
	Platform         string
	BusinessName     string
	PushName         string
	AdvAccountSigKey string
}

type IdentityKey struct {
	OurJID   types.JID `gorm:"index:idx_identity_key,unique"`
	TheirJID types.JID `gorm:"index:idx_identity_key,unique"`
	Identity string
}
type PreKey struct {
	JID      types.JID `gorm:"index:idx_pre_key,unique"`
	KeyID    types.JID `gorm:"index:idx_pre_key,unique"`
	Key      string
	Uploaded bool
}
type SenderKey struct {
	OurJID    types.JID `gorm:"index:idx_sender_key,unique"`
	ChatJID   types.JID `gorm:"index:idx_sender_key,unique"`
	SenderID  string
	SenderKey string
}
type Session struct {
	OurJID   types.JID `gorm:"index:idx_session,unique"`
	TheirJID types.JID `gorm:"index:idx_session,unique"`
	Session  string
}

// Model represents meta data of entity.
type Model struct {
	ID        uint64         `gorm:"primaryKey" json:"id" `
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

type Account struct {
	Model

	JID              types.JID
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
}
