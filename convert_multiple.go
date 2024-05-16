package tlv

import "reflect"

func _ConvertSlice(ctx _ConvertContext, next _NextConverter) (reflect.Value, error) {
	if ctx.rt.Kind() != reflect.Slice {
		return next(ctx)
	}
	switch ctx.rt.Elem().Kind() {
	case reflect.Uint8:
		return reflect.ValueOf(ctx.values[0].Value), nil
	default:
		slice := reflect.MakeSlice(ctx.rt, len(ctx.values), len(ctx.values))
		for idx, value := range ctx.values {
			conv, err := convert(ctx.rt.Elem(), TaggedValues{value}, ctx.tagopts)
			if err != nil {
				return reflect.Value{}, err
			}
			slice.Index(idx).Set(conv)
		}
		return slice, nil
	}
}

func _ConvertPointer(ctx _ConvertContext, next _NextConverter) (reflect.Value, error) {
	if ctx.rt.Kind() != reflect.Pointer {
		return next(ctx)
	}
	rtsub := ctx.rt.Elem()
	val, err := convert(rtsub, ctx.values, ctx.tagopts)
	if err != nil {
		return reflect.Value{}, err
	}
	ptr := reflect.New(val.Type())
	ptr.Elem().Set(val)
	return ptr, nil
}
