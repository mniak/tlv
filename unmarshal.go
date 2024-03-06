package tlv

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
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

var _ErrInvalidKind = errors.New("invalid kind")

type (
	_Converter interface {
		Convert(ctx _ConvertContext, next _NextConverter) (reflect.Value, error)
	}
	_ConverterFunc func(ctx _ConvertContext, next _NextConverter) (reflect.Value, error)
	_NextConverter func(ctx _ConvertContext) (reflect.Value, error)
)

func (fn _ConverterFunc) Convert(ctx _ConvertContext, next _NextConverter) (reflect.Value, error) {
	return fn(ctx, next)
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

		convertedValue, err := convert(field.Type, values, tagsplit[1:])
		if err != nil {
			return err
		}
		if convertedValue.Type() != field.Type {
			fmt.Printf("-> Converting from %+v    to    %#+v\n", convertedValue.Type(), field.Type)
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
		value, err := convert(rt.Elem(),
			TaggedValuesList{
				{
					Tag:   entry.Tag,
					Value: entry.Value,
				},
			}, nil)
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
