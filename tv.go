package tlv

import (
	"bytes"

	"go.uber.org/multierr"
)

// type (
// 	TV      []TVEntry
// 	TVEntry struct {
// 		Tag   Tag
// 		Value Value
// 	}
// )

// func (tv TV) MakeTLV() TLV {
// 	result := make(TLV, 0)
// 	for _, entry := range tv {
// 		result = append(result, entry.MakeTLVEntry())
// 	}
// 	return result
// }

// func (e TVEntry) MakeTLVEntry() Entry {
// 	return Entry{
// 		Tag:    e.Tag,
// 		Length: len(e.Value),
// 		Value:  e.Value,
// 	}
// }

// func TVFromMap(m map[Tag]Value) TV {
// 	result := make(TV, 0)
// 	for tag, value := range m {
// 		result = append(result, TVEntry{
// 			Tag:   tag,
// 			Value: value,
// 		})
// 	}
// 	return result
// }

// func FromMap(m map[Tag]Value) TLV {
// 	tv := TVFromMap(m)
// 	return tv.MakeTLV()
// }

type TaggedValue struct {
	Tag   Tag
	Value Value
}
type TaggedValuesList []TaggedValue

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

func (list TaggedValuesList) Bytes() []byte {
	var buff bytes.Buffer
	for _, item := range list {
		buff.Write(item.Value)
	}
	return buff.Bytes()
}
