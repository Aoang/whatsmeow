package gormStore

import (
	"crypto/rand"
	"encoding/hex"
	mathRand "math/rand"

	waProto "go.mau.fi/whatsmeow/binary/proto"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/util/keys"
	waLog "go.mau.fi/whatsmeow/util/log"
	"gorm.io/gorm"
)

type Container struct {
	db          *gorm.DB
	aid         uint64
	account     *Account
	allowDelete bool
}

func GetContainer(db *gorm.DB, accountID uint64) (*Container, error) {
	c := &Container{db: db, aid: accountID, account: &Account{ID: accountID}}

	if accountID == 0 {
		if err := db.Create(c.account).Error; err != nil {
			return nil, err
		}
		c.aid = c.account.ID
	} else {
		if err := db.Where("id = ?", c.aid).First(c.account).Error; err != nil {
			return nil, err
		}
	}

	return c, nil
}

func GetOrCreate(db *gorm.DB) (*Container, error) {
	c := &Container{db: db, aid: 0, account: &Account{ID: 0}}

	if err := db.Order("id DESC").First(c.account).Error; err == nil {
		c.aid = c.account.ID
		return c, nil
	}

	return GetContainer(db, 0)
}

func (d *Container) AllowDelete() *Container { d.allowDelete = true; return d }
func (d *Container) AID() uint64             { return d.aid }

func (d *Container) Device(log waLog.Logger) *store.Device {
	device := &store.Device{
		Log:        log,
		Identities: d, Sessions: d, PreKeys: d, SenderKeys: d, AppStateKeys: d,
		AppState: d, Contacts: d, ChatSettings: d, MsgSecrets: d, Container: d,
		DatabaseErrorHandler: func(*store.Device, string, int, error) (retry bool) {
			return false
		},
	}

	if d.account.JID == "" {
		device.NoiseKey = keys.NewKeyPair()
		device.IdentityKey = keys.NewKeyPair()
		device.SignedPreKey = device.IdentityKey.CreateSignedPreKey(1)
		device.RegistrationID = mathRand.Uint32()
		device.AdvSecretKey = make([]byte, 32)

		if _, err := rand.Read(device.AdvSecretKey); err != nil {
			panic(err)
		}
	} else {
		device.NoiseKey = parseKeyPairFromPrivateKey(d.account.NoiseKey)
		device.IdentityKey = parseKeyPairFromPrivateKey(d.account.IdentityKey) //    *keys.KeyPair
		device.SignedPreKey = &keys.PreKey{
			KeyPair:   *parseKeyPairFromPrivateKey(d.account.SignedPreKey),
			KeyID:     d.account.SignedPreKeyID,
			Signature: (*[64]byte)(hexDecode(d.account.SignedPreKeySig)),
		}

		device.RegistrationID = d.account.RegistrationID
		device.AdvSecretKey = hexDecode(d.account.AdvKey)
		device.Account = &waProto.ADVSignedDeviceIdentity{
			Details:             hexDecode(d.account.AdvDetails),
			AccountSignatureKey: hexDecode(d.account.AdvAccountSigKey),
			AccountSignature:    hexDecode(d.account.AdvAccountSig),
			DeviceSignature:     hexDecode(d.account.AdvDeviceSig),
		}

		device.ID = parseJID(d.account.JID)
		device.Platform = d.account.Platform
		device.BusinessName = d.account.BusinessName
		device.PushName = d.account.PushName
		device.Initialized = true
	}

	return device
}

func hexDecode(s string) []byte {
	data, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

func parseKeyPairFromPrivateKey(s string) *keys.KeyPair {
	return keys.NewKeyPairFromPrivateKey(*(*[32]byte)(hexDecode(s)))
}

func parseJID(s string) *types.JID {
	jid, err := types.ParseJID(s)
	if err != nil {
		panic(err)
	}

	return &jid
}

var (
	_ store.IdentityStore        = (*Container)(nil)
	_ store.SessionStore         = (*Container)(nil)
	_ store.PreKeyStore          = (*Container)(nil)
	_ store.SenderKeyStore       = (*Container)(nil)
	_ store.AppStateSyncKeyStore = (*Container)(nil)
	_ store.AppStateStore        = (*Container)(nil)
	_ store.ContactStore         = (*Container)(nil)
	_ store.MsgSecretStore       = (*Container)(nil)
	_ store.DeviceContainer      = (*Container)(nil)
)
