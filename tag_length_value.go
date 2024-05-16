package tlv

import (
	"bytes"
	"fmt"
)

type (
	TLV   []Entry
	Entry struct {
		Tag    Tag
		Length int
		Value  Value
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

func (tlv TLV) MakeValuesList(tlList TL) (TaggedValues, error) {
	padData := func(data []byte, length int) []byte {
		if len(data) < length {
			data = append(make([]byte, length-len(data)), data...)
		}
		return data
	}

	var results TLV
	for _, tl := range tlList {
		value := tlv.GetValue(tl.Tag)
		if len(value) == 0 {
			return nil, fmt.Errorf("missing value for tag %s", tl.Tag)
		}
		if len(value) != tl.Length {
			return nil, fmt.Errorf("value of tag %s has a different length than the specified", tl.Tag)
		}
		value = padData(value, tl.Length)
		results = append(results, Entry{
			Tag:    tl.Tag,
			Length: tl.Length,
			Value:  value,
		})
	}
	return results.Values(), nil
}

func (tlv TLV) GetList(t Tag) TaggedValues {
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

func (tlv TLV) Values() TaggedValues {
	list := make(TaggedValues, 0)
	for _, item := range tlv {
		list = append(list, TaggedValue{
			Tag:   item.Tag,
			Value: item.Value,
		})
	}
	return list
}

func (tlv TLV) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	for _, entry := range tlv {
		tagBytes, err := entry.Tag.Encode()
		if err != nil {
			return nil, err
		}
		buf.Write(tagBytes)
		// Encode TAG according to BER rules
		lenValue := len(entry.Value)
		buf.WriteByte(byte(lenValue))
		buf.Write(entry.Value)
	}
	return buf.Bytes(), nil
}
