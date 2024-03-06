package tlv

import (
	"encoding"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"golang.org/x/exp/slices"
)

func UnmarshalBER(data []byte, v any) error {
	if u, is := v.(Unmarshaler); is {
		return u.Unmarshal(data)
	}

	tlv, err := ParseBER(data)
	if err != nil {
		return err
	}

	return tlv.CopyTo(v)
}

func convertKey(rt reflect.Type, tag Tag) (any, error) {
	switch rt.Kind() {
	case reflect.String:
		return tag.String(), nil
	case reflect.Int:
		return int(tag), nil
	case reflect.Uint16:
		return uint16(tag), nil
	default:
		return nil, fmt.Errorf("tlv unmarshal: invalid map key kind %s", rt.Kind())
	}
}

type Unmarshaler interface {
	Unmarshal(data []byte) error
}

var unmarshalerType = reflect.TypeOf((*Unmarshaler)(nil)).Elem()

func convertValues(rt reflect.Type, values TaggedValuesList, tagopts []string) (reflect.Value, error) {
	firstValue := []byte(values[0].Value)

	switch {
	case rt.Implements(unmarshalerType):
		reflect.New(rt)
		return reflect.Value{}, nil
	case reflect.PointerTo(rt).Implements(unmarshalerType):

		rv := reflect.New(rt)
		rvi := rv.Interface()
		bu := rvi.(Unmarshaler)

		if err := bu.Unmarshal(firstValue); err != nil {
			return reflect.Value{}, err
		}

		return reflect.ValueOf(bu).Elem(), nil

	}

	switch rt {
	case reflect.TypeOf(TLV{}):
		subtlv, err := ParseBER(firstValue)
		if err != nil {
			return reflect.Value{}, err
		}
		return reflect.ValueOf(subtlv), nil
	case reflect.TypeOf(TL{}):
		subtl, err := ParseBERTL(firstValue)
		if err != nil {
			return reflect.Value{}, err
		}
		return reflect.ValueOf(subtl), nil
	}

	switch rt.Kind() {
	case reflect.String:
		if slices.Contains(tagopts, "hex") {
			return reflect.ValueOf(strings.ToUpper(hex.EncodeToString(firstValue))), nil
		}
		return reflect.ValueOf(string(firstValue)), nil
	case reflect.Int:
		return reflect.ValueOf(int(getIntFromBytes(firstValue))), nil
	case reflect.Uint64:
		return reflect.ValueOf(uint64(getIntFromBytes(firstValue))), nil
	case reflect.Slice:
		switch rt.Elem().Kind() {
		case reflect.Uint8:
			return reflect.ValueOf(firstValue), nil
		default:
			slice := reflect.MakeSlice(rt, len(values), len(values))
			for idx, value := range values {
				conv, err := convertValues(rt.Elem(), TaggedValuesList{value}, tagopts)
				if err != nil {
					return reflect.Value{}, err
				}
				slice.Index(idx).Set(conv)
			}
			return slice, nil
		}
	case reflect.Interface:
		if rt.NumMethod() > 0 {
			return reflect.Value{}, errors.New("tlv unmarshal: interface can't have methods")
		}
		return reflect.ValueOf(firstValue), nil
	case reflect.Struct:
		obj := reflect.New(rt).Elem()
		switch bu := obj.Interface().(type) {
		case encoding.BinaryUnmarshaler:
			if err := bu.UnmarshalBinary(firstValue); err != nil {
				return reflect.Value{}, err
			}
			return reflect.ValueOf(bu), nil
		case *encoding.BinaryUnmarshaler:
			if err := (*bu).UnmarshalBinary(firstValue); err != nil {
				return reflect.Value{}, err
			}
			return reflect.ValueOf(bu), nil
		default:
		}

		subtlv, err := ParseBER(firstValue)
		if err != nil {
			return reflect.Value{}, err
		}
		if err := copyToStruct(subtlv, rt, obj); err != nil {
			return reflect.Value{}, err
		}
		return obj, nil
	case reflect.Map:
		subtlv, err := ParseBER(firstValue)
		if err != nil {
			return reflect.Value{}, err
		}
		obj := reflect.MakeMap(rt)
		if err := copyToMap(subtlv, rt, obj); err != nil {
			return reflect.Value{}, err
		}
		return obj, nil
	case reflect.Pointer:
		rtsub := rt.Elem()
		val, err := convertValues(rtsub, values, tagopts)
		if err != nil {
			return reflect.Value{}, err
		}
		ptr := reflect.New(val.Type())
		ptr.Elem().Set(val)
		return ptr, nil

	default:
		return reflect.Value{}, fmt.Errorf("tlv unmarshal: invalid value kind %s", rt.Kind())
	}
}

func copyToStruct(tlv TLV, rt reflect.Type, rv reflect.Value) error {
	for i := 0; i < rt.NumField(); i++ {
		field := rt.Field(i)
		fieldtag := field.Tag.Get("tlv")
		if len(fieldtag) == 0 {
			continue
		}
		tagsplit := strings.Split(fieldtag, ",")
		tlvtagname := tagsplit[0]

		if tlvtagname == "raw" {
			if field.Type == reflect.TypeOf(tlv) {
				rv.Field(i).Set(reflect.ValueOf(tlv))
			}
			continue
		}

		tlvtagi64, err := strconv.ParseInt(tlvtagname, 16, 32)
		if err != nil {
			return fmt.Errorf("tlv unmarshal: invalid tag '%s'", tlvtagname)
		}

		values := tlv.GetList(Tag(tlvtagi64))
		if len(values) == 0 {
			continue
		}

		convertedValue, err := convertValues(field.Type, values, tagsplit[1:])
		if err != nil {
			return err
		}
		if convertedValue.Type() != field.Type {
			convertedValue = convertedValue.Convert(field.Type)
		}
		rv.Field(i).Set(convertedValue)
	}
	return nil
}

func copyToMap(tlv TLV, rt reflect.Type, rv reflect.Value) error {
	for _, entry := range tlv {
		key, err := convertKey(rt.Key(), entry.Tag)
		if err != nil {
			return err
		}
		value, err := convertValues(rt.Elem(), TaggedValuesList{{
			Tag:   entry.Tag,
			Value: entry.Value,
		}}, nil)
		if err != nil {
			return err
		}

		rv.SetMapIndex(
			reflect.ValueOf(key).Convert(rt.Key()),
			value.Convert(rt.Elem()),
		)
	}
	return nil
}

func (tlv TLV) CopyTo(v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return errors.New("cannot copy to non-pointer or nil")
	}
	rv = rv.Elem()
	rt := reflect.TypeOf(v).Elem()

	switch rt.Kind() {
	case reflect.Struct:
		return copyToStruct(tlv, rt, rv)
	case reflect.Map:
		if rv.IsNil() {
			rv.Set(reflect.MakeMap(rt))
		}
		return copyToMap(tlv, rt, rv)
	default:
		return fmt.Errorf("tlv unmarshal: invalid kind %s", rv.Kind())
	}
}

func getIntFromBytes(data []byte) int64 {
	var result int64
	for _, b := range data {
		result *= 256
		result += int64(b)
	}
	return result
}
