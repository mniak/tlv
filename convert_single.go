package tlv

import (
	"encoding/hex"
	"errors"
	"reflect"
	"strings"

	"golang.org/x/exp/slices"
)

func _ConvertUnmarshaler(ctx _ConvertContext, next _NextConverter) (reflect.Value, error) {
	if !reflect.PointerTo(ctx.rt).Implements(unmarshalerType) {
		return next(ctx)
	}
	rv := reflect.New(ctx.rt)
	rvi := rv.Interface()
	bu := rvi.(Unmarshaler)

	if err := bu.Unmarshal(ctx.values[0].Value); err != nil {
		return reflect.Value{}, err
	}

	return reflect.ValueOf(bu).Elem(), nil
}

func _ConvertTLV(ctx _ConvertContext, next _NextConverter) (reflect.Value, error) {
	if ctx.rt != reflect.TypeOf(TLV{}) {
		return next(ctx)
	}
	subtlv, err := ParseBER(ctx.values[0].Value)
	if err != nil {
		return reflect.Value{}, err
	}
	return reflect.ValueOf(subtlv), nil
}

func _ConvertTL(ctx _ConvertContext, next _NextConverter) (reflect.Value, error) {
	if ctx.rt != reflect.TypeOf(TL{}) {
		return next(ctx)
	}

	subtl, err := ParseBERTL(ctx.values[0].Value)
	if err != nil {
		return reflect.Value{}, err
	}
	return reflect.ValueOf(subtl), nil
}

func _ConvertByte(ctx _ConvertContext, next _NextConverter) (reflect.Value, error) {
	if ctx.rt.Kind() != reflect.Uint8 {
		return next(ctx)
	}
	return reflect.ValueOf(ctx.values[0].Value[0]), nil
}

func _ConvertString(ctx _ConvertContext, next _NextConverter) (reflect.Value, error) {
	if ctx.rt.Kind() != reflect.String {
		return next(ctx)
	}
	if slices.Contains(ctx.tagopts, "hex") {
		return reflect.ValueOf(strings.ToUpper(hex.EncodeToString(ctx.values[0].Value))), nil
	}
	return reflect.ValueOf(string(ctx.values[0].Value)), nil
}

func _ConvertInt(ctx _ConvertContext, next _NextConverter) (reflect.Value, error) {
	if ctx.rt.Kind() != reflect.Int {
		return next(ctx)
	}
	return reflect.ValueOf(int(getIntFromBytes(ctx.values[0].Value))), nil
}

func _ConvertUInt64(ctx _ConvertContext, next _NextConverter) (reflect.Value, error) {
	if ctx.rt.Kind() != reflect.Uint64 {
		return next(ctx)
	}
	return reflect.ValueOf(uint64(getIntFromBytes(ctx.values[0].Value))), nil
}

func _ConvertInterface(ctx _ConvertContext, next _NextConverter) (reflect.Value, error) {
	if ctx.rt.Kind() != reflect.Interface {
		return next(ctx)
	}
	if ctx.rt.NumMethod() > 0 {
		return reflect.Value{}, errors.New("tlv unmarshal: interface can't have methods")
	}
	return reflect.ValueOf([]byte(ctx.values[0].Value)), nil
}
