package gormStore

import (
	"encoding/hex"
	"errors"
	"time"

	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/util/keys"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func (d *Container) PutDevice(store *store.Device) error {
	account := *d.account

	account.JID = store.ID.String()

	account.RegistrationID = store.RegistrationID

	account.NoiseKey = hex.EncodeToString(store.NoiseKey.Priv[:])
	account.IdentityKey = hex.EncodeToString(store.IdentityKey.Priv[:])

	account.SignedPreKey = hex.EncodeToString(store.SignedPreKey.Priv[:])
	account.SignedPreKeyID = store.SignedPreKey.KeyID
	account.SignedPreKeySig = hex.EncodeToString(store.SignedPreKey.Signature[:])

	account.AdvKey = hex.EncodeToString(store.AdvSecretKey)
	account.AdvDetails = hex.EncodeToString(store.Account.Details)
	account.AdvAccountSig = hex.EncodeToString(store.Account.AccountSignature)
	account.AdvDeviceSig = hex.EncodeToString(store.Account.DeviceSignature)

	account.Platform = store.Platform
	account.BusinessName = store.BusinessName
	account.PushName = store.PushName

	return d.db.Clauses(clause.OnConflict{UpdateAll: true}).Create(&account).Error
}

func (d *Container) DeleteDevice(_ *store.Device) error {
	if !d.allowDelete {
		return nil
	}
	return d.db.Delete(d.account).Error
}

func (d *Container) PutIdentity(address string, key [32]byte) error {
	return d.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "aid"}, {Name: "their_jid"}},
		DoUpdates: clause.AssignmentColumns([]string{"identity"}),
	}).Create(&IdentityKey{
		AID:      d.account.ID,
		TheirJID: address,
		Identity: hex.EncodeToString(key[:]),
	}).Error
}

func (d *Container) DeleteAllIdentities(phone string) error {
	return d.specify().Where("their_jid LIKE ?", phone+":%").Delete(&IdentityKey{}).Error
}

func (d *Container) DeleteIdentity(address string) error {
	return d.specify().Where("their_jid LIKE ?", address).Delete(&IdentityKey{}).Error
}

func (d *Container) IsTrustedIdentity(address string, key [32]byte) (bool, error) {
	var arg IdentityKey
	if err := d.specify().Where("their_jid = ?", address).First(&arg).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return true, nil
		}
		return false, err
	}
	return arg.Identity == hex.EncodeToString(key[:]), nil
}

func (d *Container) specify() *gorm.DB {
	return d.db.Where("aid = ?", d.aid)
}

func (d *Container) GetSession(address string) ([]byte, error) {
	var arg Session
	if err := d.specify().Where("their_jid = ?", address).First(&arg).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return hex.DecodeString(arg.Session)
}

func (d *Container) HasSession(address string) (bool, error) {
	var has bool
	if err := d.db.Model(&Session{}).Select("true").Where(
		"aid = ? AND their_jid = ?", d.aid, address).First(&has).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}
	return has, nil
}

func (d *Container) PutSession(address string, session []byte) error {
	return d.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "aid"}, {Name: "their_jid"}},
		DoUpdates: clause.AssignmentColumns([]string{"session"}),
	}).Create(&Session{
		AID:      d.account.ID,
		TheirJID: address,
		Session:  hex.EncodeToString(session),
	}).Error
}

func (d *Container) DeleteAllSessions(phone string) error {
	return d.specify().Where("their_jid LIKE ?", phone+":%").Delete(&Session{}).Error
}

func (d *Container) DeleteSession(address string) error {
	return d.specify().Where("their_jid = ?", address).Delete(&Session{}).Error
}

func (d *Container) getPreKeyMaxID(tx *gorm.DB) (uint32, error) {
	var maxID uint32
	if err := tx.Model(&PreKey{}).Select("COALESCE(MAX(key_id), 0)").Where("aid = ?", d.aid).
		Find(&maxID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return 0, nil
		}
		return 0, err
	}

	return maxID, nil
}

func (d *Container) GetOrGenPreKeys(count uint32) ([]*keys.PreKey, error) {
	var arr []*PreKey
	err := d.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("aid = ? AND uploaded = FALSE", d.aid).
			Order("key_id").Limit(int(count)).Find(&arr).Error; err != nil {
			return err
		}
		if len(arr) >= int(count) {
			return nil
		}
		newArr := make([]*PreKey, int(count)-len(arr))
		keyID, err := d.getPreKeyMaxID(tx)
		if err != nil {
			return err
		}
		for i := range newArr {
			keyID++
			key := keys.NewPreKey(keyID)
			newArr[i] = &PreKey{
				AID:   d.aid,
				KeyID: keyID,
				Key:   hex.EncodeToString(key.Priv[:]),
			}
		}

		if err = tx.Create(&newArr).Error; err != nil {
			return err
		}

		arr = append(arr, newArr...)

		return nil
	})

	if err != nil {
		return nil, err
	}

	resp := make([]*keys.PreKey, 0, count)
	for _, v := range arr {
		k := v.ToKey()
		if k == nil {
			return nil, errors.New("parse pre key error")
		}
		resp = append(resp, k)
	}

	return resp, nil
}

func (d *Container) GenOnePreKey() (*keys.PreKey, error) {
	var key *keys.PreKey
	err := d.db.Transaction(func(tx *gorm.DB) error {
		keyID, err := d.getPreKeyMaxID(tx)
		if err != nil {
			return err
		}
		key = keys.NewPreKey(keyID + 1)

		return tx.Create(&PreKey{
			AID:      d.aid,
			KeyID:    key.KeyID,
			Key:      hex.EncodeToString(key.Priv[:]),
			Uploaded: true,
		}).Error
	})
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (d *Container) GetPreKey(id uint32) (*keys.PreKey, error) {
	var arg PreKey
	if err := d.specify().Where("key_id = ?", id).First(&arg).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if key := arg.ToKey(); key != nil {
		return key, nil
	}
	return nil, errors.New("parse key error")
}

func (d *Container) RemovePreKey(id uint32) error {
	return d.specify().Where("key_id = ?", id).Delete(&PreKey{}).Error
}

func (d *Container) MarkPreKeysAsUploaded(upToID uint32) error {
	return d.db.Model(&PreKey{}).Where("aid = ? AND key_id = ?", d.aid, upToID).
		Update("uploaded", true).Error
}

func (d *Container) UploadedPreKeyCount() (int, error) {
	var count int64
	if err := d.db.Model(&PreKey{}).Where("aid = ? AND uploaded = ?", d.aid, true).
		Count(&count).Error; err != nil {
		return 0, err
	}
	return int(count), nil
}

func (d *Container) PutSenderKey(group, user string, session []byte) error {
	return d.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "aid"}, {Name: "chat_jid"}, {Name: "sender_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"sender_key"}),
	}).Create(&SenderKey{
		AID:       d.aid,
		ChatJID:   group,
		SenderID:  user,
		SenderKey: hex.EncodeToString(session),
	}).Error
}

func (d *Container) GetSenderKey(group, user string) ([]byte, error) {
	var arg SenderKey
	if err := d.specify().Where("chat_jid = ? AND sender_id = ?", group, user).First(&arg).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return hex.DecodeString(arg.SenderKey)
}

func (d *Container) PutAppStateSyncKey(id []byte, key store.AppStateSyncKey) error {
	return d.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "aid"}, {Name: "key_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"key_data", "timestamp", "fingerprint"}),
	}).Create(&AppStateSyncKey{
		AID:         d.aid,
		KeyID:       hex.EncodeToString(id),
		KeyData:     hex.EncodeToString(key.Data),
		Timestamp:   key.Timestamp,
		Fingerprint: hex.EncodeToString(key.Fingerprint),
	}).Error
}

func (d *Container) GetAppStateSyncKey(id []byte) (*store.AppStateSyncKey, error) {
	var arg AppStateSyncKey
	err := d.specify().Where("key_id = ?", hex.EncodeToString(id)).First(&arg).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	k := &store.AppStateSyncKey{
		Data:        nil,
		Fingerprint: nil,
		Timestamp:   arg.Timestamp,
	}
	if k.Data, err = hex.DecodeString(arg.KeyData); err != nil {
		return nil, err
	}
	if k.Fingerprint, err = hex.DecodeString(arg.Fingerprint); err != nil {
		return nil, err
	}
	return k, nil
}

func (d *Container) PutAppStateVersion(name string, version uint64, hash [128]byte) error {
	return d.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "aid"}, {Name: "name"}},
		DoUpdates: clause.AssignmentColumns([]string{"version", "hash"}),
	}).Create(&AppStateVersion{
		AID:     d.aid,
		Name:    name,
		Version: version,
		Hash:    hex.EncodeToString(hash[:]),
	}).Error
}

func (d *Container) GetAppStateVersion(name string) (uint64, [128]byte, error) {
	var arg AppStateVersion
	if err := d.specify().Where("name = ?", name).First(&arg).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return 0, [128]byte{}, nil
		}
		return 0, [128]byte{}, err
	}
	hash, err := hex.DecodeString(arg.Hash)
	if err != nil || len(hash) != 128 {
		return 0, [128]byte{}, errors.New("parse hash error")
	}
	return arg.Version, *(*[128]byte)(hash), nil
}

func (d *Container) DeleteAppStateVersion(name string) error {
	return d.specify().Where("name = ?", name).Delete(&AppStateVersion{}).Error
}

func (d *Container) PutAppStateMutationMACs(name string, version uint64, mutations []store.AppStateMutationMAC) error {
	arr := make([]*AppStateMutationMac, len(mutations))
	for i := range arr {
		arr[i] = &AppStateMutationMac{
			AID:      d.aid,
			Name:     name,
			Version:  version,
			IndexMac: hex.EncodeToString(mutations[i].IndexMAC),
			ValueMac: hex.EncodeToString(mutations[i].ValueMAC),
		}
	}
	return d.db.Create(&arr).Error
}

func (d *Container) DeleteAppStateMutationMACs(name string, indexMACs [][]byte) error {
	arr := make([]string, len(indexMACs))
	for i := range arr {
		arr[i] = hex.EncodeToString(indexMACs[i])
	}
	return d.db.Where("aid = ? AND name = ? AND index_mac IN ?", d.aid, name, arr).
		Delete(&AppStateMutationMac{}).Error
}

func (d *Container) GetAppStateMutationMAC(name string, indexMAC []byte) ([]byte, error) {
	var arg AppStateMutationMac
	if err := d.specify().Where("name = ? AND index_mac = ?", name, hex.EncodeToString(indexMAC)).First(&arg).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return hex.DecodeString(arg.ValueMac)
}

// PutPushName 的行为比较鬼畜
// 数据库会先查找用户，然后对比 pushName 是否一致，来决定 bool 和 string 返回的什么。
// 如果变更了，就是 true 和之前的 pushName，否则保持空
func (d *Container) PutPushName(user types.JID, pushName string) (bool, string, error) {
	var (
		arg          Contact
		isChange     bool
		previousName string
	)
	if err := d.specify().Where("their_jid = ?", user.String()).First(&arg).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return false, "", err
		}
		arg.AID = d.aid
		arg.TheirJID = user.String()
	}

	if arg.PushName != pushName {
		isChange = true
		previousName = arg.PushName
		arg.PushName = pushName
	}

	return isChange, previousName, d.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "aid"}, {Name: "their_jid"}},
		DoUpdates: clause.AssignmentColumns([]string{"push_name"}),
	}).Create(&arg).Error
}

func (d *Container) PutBusinessName(user types.JID, businessName string) (bool, string, error) {
	var (
		arg          Contact
		isChange     bool
		previousName string
	)
	if err := d.specify().Where("their_jid = ?", user.String()).First(&arg).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return false, "", err
		}
		arg.AID = d.aid
		arg.TheirJID = user.String()
	}

	if arg.BusinessName != businessName {
		isChange = true
		previousName = arg.BusinessName
		arg.BusinessName = businessName
	}

	return isChange, previousName, d.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "aid"}, {Name: "their_jid"}},
		DoUpdates: clause.AssignmentColumns([]string{"business_name"}),
	}).Create(&Contact{
		AID:          d.aid,
		TheirJID:     user.String(),
		BusinessName: businessName,
	}).Error
}

func (d *Container) PutContactName(user types.JID, fullName, firstName string) error {
	return d.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "aid"}, {Name: "their_jid"}},
		DoUpdates: clause.AssignmentColumns([]string{"full_name", "first_name"}),
	}).Create(&Contact{
		AID:       d.aid,
		TheirJID:  user.String(),
		FirstName: firstName,
		FullName:  fullName,
	}).Error
}

func (d *Container) PutAllContactNames(contacts []store.ContactEntry) error {
	arr := make([]*Contact, len(contacts))
	for i := range arr {
		arr[i] = &Contact{
			AID:       d.aid,
			TheirJID:  contacts[i].JID.String(),
			FirstName: contacts[i].FirstName,
			FullName:  contacts[i].FullName,
		}
	}

	return d.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "aid"}, {Name: "their_jid"}},
		DoUpdates: clause.AssignmentColumns([]string{"full_name", "first_name"}),
	}).Create(&arr).Error
}

func (d *Container) GetContact(user types.JID) (types.ContactInfo, error) {
	var arg Contact

	if err := d.specify().Where("their_jid = ?", user.String()).First(&arg).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return types.ContactInfo{}, nil
		}
		return types.ContactInfo{}, err
	}

	return types.ContactInfo{
		Found:        true,
		FirstName:    arg.FirstName,
		FullName:     arg.FullName,
		PushName:     arg.PushName,
		BusinessName: arg.BusinessName,
	}, nil
}

func (d *Container) GetAllContacts() (map[types.JID]types.ContactInfo, error) {
	var arg []*Contact
	if err := d.specify().Find(&arg).Error; err != nil {
		return nil, err
	}

	m := make(map[types.JID]types.ContactInfo)
	for _, v := range arg {
		jid, _ := types.ParseJID(v.TheirJID)
		m[jid] = types.ContactInfo{
			Found:        true,
			FirstName:    v.FirstName,
			FullName:     v.FullName,
			PushName:     v.PushName,
			BusinessName: v.BusinessName,
		}
	}

	return m, nil
}

func (d *Container) PutMutedUntil(chat types.JID, mutedUntil time.Time) error {
	return d.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "aid"}, {Name: "chat_jid"}},
		DoUpdates: clause.AssignmentColumns([]string{"muted_until"}),
	}).Create(&ChatSetting{
		AID:        d.aid,
		ChatJID:    chat.String(),
		MutedUntil: mutedUntil.Unix(),
	}).Error
}

func (d *Container) PutPinned(chat types.JID, pinned bool) error {
	return d.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "aid"}, {Name: "chat_jid"}},
		DoUpdates: clause.AssignmentColumns([]string{"pinned"}),
	}).Create(&ChatSetting{
		AID:     d.aid,
		ChatJID: chat.String(),
		Pinned:  pinned,
	}).Error
}

func (d *Container) PutArchived(chat types.JID, archived bool) error {
	return d.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "aid"}, {Name: "chat_jid"}},
		DoUpdates: clause.AssignmentColumns([]string{"archived"}),
	}).Create(&ChatSetting{
		AID:      d.aid,
		ChatJID:  chat.String(),
		Archived: archived,
	}).Error
}

func (d *Container) GetChatSettings(chat types.JID) (types.LocalChatSettings, error) {
	var arg ChatSetting
	if err := d.specify().Where("chat_jid = ?", chat.String()).First(&arg).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return types.LocalChatSettings{}, nil
		}
		return types.LocalChatSettings{}, err
	}

	var t time.Time
	if arg.MutedUntil != 0 {
		t = time.Unix(arg.MutedUntil, 0)
	}

	return types.LocalChatSettings{
		Found:      true,
		MutedUntil: t,
		Pinned:     arg.Pinned,
		Archived:   arg.Archived,
	}, nil
}
