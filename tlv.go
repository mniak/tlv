package tlv

import (
	"bytes"

	"go.uber.org/multierr"
)

type (
	TLV   []Entry
	Entry struct {
		Tag    Tag
		Length int
		Value  Value
	}
)

type (
	TL      []TLEntry
	TLEntry struct {
		Tag    Tag
		Length int
	}
)

func (tlv TLV) Index(i int) (Entry, bool) {
	if i >= len(tlv) {
		return Entry{}, false
	}
	entry := tlv[i]
	return entry, true
}

func (tlv TLV) GetValue(t Tag) Value {
	for _, entry := range tlv {
		if entry.Tag == t {
			return entry.Value
		}
	}
	return nil
}

type ValuesList []Value

func (list ValuesList) Bytes() []byte {
	var buff bytes.Buffer
	for _, item := range list {
		buff.Write(item)
	}
	return buff.Bytes()
}

func (list ValuesList) AsBERTLV() ([]TLV, error) {
	var errs error
	var result []TLV
	for _, val := range list {
		ber, err := ParseBER(val)
		if err != nil {
			multierr.AppendInto(&errs, err)
		} else {
			result = append(result, ber)
		}
	}
	return result, errs
}

func (tlv TLV) GetList(t Tag) ValuesList {
	var result []Value
	for _, entry := range tlv {
		if entry.Tag == t && entry.Value != nil {
			result = append(result, entry.Value)
		}
	}
	return result
}

func (tlv TLV) Values() ValuesList {
	list := make(ValuesList, 0)
	for _, item := range tlv {
		list = append(list, item.Value)
	}
	return list
}
