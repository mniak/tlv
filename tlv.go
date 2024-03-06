package tlv

import (
	"bytes"
	"fmt"

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

func (tlv TLV) MakeValuesList(list TL) (TaggedValuesList, error) {
	padData := func(data []byte, length int) []byte {
		if len(data) < length {
			data = append(make([]byte, length-len(data)), data...)
		}
		return data
	}

	var results TLV
	for _, entry := range list {
		value := tlv.GetValue(entry.Tag)
		if len(value) == 0 {
			return nil, fmt.Errorf("missing data for object list: tag %s", entry.Tag)
		}
		value = padData(value, entry.Length)
		results = append(results, Entry{
			Tag:    entry.Tag,
			Length: entry.Length,
			Value:  value,
		})
	}
	return results.Values(), nil
}

func (tlv TLV) GetList(t Tag) TaggedValuesList {
	var result []TaggedValue
	for _, entry := range tlv {
		if entry.Tag == t && entry.Value != nil {
			result = append(result, TaggedValue{
				Tag:   entry.Tag,
				Value: entry.Value,
			})
		}
	}
	return result
}

func (tlv TLV) Values() TaggedValuesList {
	list := make(TaggedValuesList, 0)
	for _, item := range tlv {
		list = append(list, TaggedValue{
			Tag:   item.Tag,
			Value: item.Value,
		})
	}
	return list
}

type TaggedValue struct {
	Tag   Tag
	Value Value
}
type TaggedValuesList []TaggedValue

func (list TaggedValuesList) Bytes() []byte {
	var buff bytes.Buffer
	for _, item := range list {
		buff.Write(item.Value)
	}
	return buff.Bytes()
}

func (list TaggedValuesList) AsBERTLV() ([]TLV, error) {
	var errs error
	var result []TLV
	for _, val := range list {
		ber, err := ParseBER(val.Value)
		if err != nil {
			multierr.AppendInto(&errs, err)
		} else {
			result = append(result, ber)
		}
	}
	return result, errs
}

func (vl TaggedValuesList) GetValue(t Tag) Value {
	for _, entry := range vl {
		if entry.Tag == t {
			return entry.Value
		}
	}
	return nil
}
