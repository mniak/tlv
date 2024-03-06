package tlv

import (
	"encoding"
	"reflect"
)

type _ConvertStruct struct{}

func (_ConvertStruct) Convert(ctx _ConvertContext, next _NextConverter) (reflect.Value, error) {
	if ctx.rt.Kind() != reflect.Struct {
		return next(ctx)
	}
	obj := reflect.New(ctx.rt).Elem()
	switch bu := obj.Interface().(type) {
	case encoding.BinaryUnmarshaler:
		if err := bu.UnmarshalBinary(ctx.values[0].Value); err != nil {
			return reflect.Value{}, err
		}
		return reflect.ValueOf(bu), nil
	case *encoding.BinaryUnmarshaler:
		if err := (*bu).UnmarshalBinary(ctx.values[0].Value); err != nil {
			return reflect.Value{}, err
		}
		return reflect.ValueOf(bu), nil
	default:
	}

	subtlv, err := ParseBER(ctx.values[0].Value)
	if err != nil {
		return reflect.Value{}, err
	}
	if err := copyToStruct(subtlv, ctx.rt, obj); err != nil {
		return reflect.Value{}, err
	}
	return obj, nil
}

type _ConvertMap struct{}

func (_ConvertMap) Convert(ctx _ConvertContext, next _NextConverter) (reflect.Value, error) {
	if ctx.rt.Kind() != reflect.Map {
		return next(ctx)
	}
	subtlv, err := ParseBER(ctx.values[0].Value)
	if err != nil {
		return reflect.Value{}, err
	}
	obj := reflect.MakeMap(ctx.rt)
	if err := copyToMap(subtlv, ctx.rt, obj); err != nil {
		return reflect.Value{}, err
	}
	return obj, nil
}
