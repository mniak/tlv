package tlv

import (
	"bytes"
	"fmt"
)

type TaggedValue struct {
	Tag   Tag
	Value Value
}

type TaggedValues []TaggedValue

func TaggedValuesListFromMap(m map[Tag]Value) TaggedValues {
	result := make(TaggedValues, 0)
	for tag, value := range m {
		result = append(result, TaggedValue{
			Tag:   tag,
			Value: value,
		})
	}
	return result
}

func (list TaggedValues) GetValue(t Tag) Value {
	for _, entry := range list {
		if entry.Tag == t {
			return entry.Value
		}
	}
	return nil
}

func (list TaggedValues) ValuesBytes() []byte {
	var buff bytes.Buffer
	for _, item := range list {
		buff.Write(item.Value)
	}
	return buff.Bytes()
}

func (list TaggedValues) MakeTLV() TLV {
	tlv := make(TLV, 0)
	for _, tv := range list {
		tlv = append(tlv, Entry{
			Tag:    tv.Tag,
			Length: len(tv.Value),
			Value:  tv.Value,
		})
	}
	return tlv
}

func (list TaggedValues) Select(tagList TL) (TaggedValues, error) {
	padData := func(data []byte, length int) []byte {
		if len(data) < length {
			data = append(make([]byte, length-len(data)), data...)
		}
		return data
	}

	var results TaggedValues
	for _, entry := range tagList {
		value := list.GetValue(entry.Tag)
		if len(value) == 0 {
			return nil, fmt.Errorf("missing data for object list: tag %s", entry.Tag)
		}
		value = padData(value, entry.Length)
		results = append(results, TaggedValue{
			Tag:   entry.Tag,
			Value: value,
		})
	}
	return results, nil
}
