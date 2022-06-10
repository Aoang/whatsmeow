package gormStore

import (
	"gorm.io/gorm"
)

type Container struct {
	db          *gorm.DB
	aid         uint64
	account     *Account
	allowDelete bool
}

func NewContainer(db *gorm.DB, accountID uint64) (*Container, error) {
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

func (d *Container) AllowDelete() *Container {
	d.allowDelete = true
	return d
}
