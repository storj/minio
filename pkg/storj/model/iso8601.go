package model

import "time"

type ISO8601 time.Time

const iso8601TimeFormat = "2006-01-02T15:04:05.000Z"

func (i ISO8601) MarshalText() ([]byte, error) {
	return []byte(time.Time(i).UTC().Format(iso8601TimeFormat)), nil
}
