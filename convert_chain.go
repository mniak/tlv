package tlv

import (
	"reflect"
	"sync"
)

var (
	initConverterOnce sync.Once
	converter         _NextConverter
)

func initConverter() {
	initConverterOnce.Do(func() {
		chain := []_Converter{
			_ConverterFunc(_ConvertPointer),
			_ConverterFunc(_ConvertUnmarshaler),
			_ConverterFunc(_ConvertTLV),
			_ConverterFunc(_ConvertTL),
			_ConverterFunc(_ConvertString),
			_ConverterFunc(_ConvertInt),
			_ConverterFunc(_ConvertUInt64),
			_ConverterFunc(_ConvertSlice),
			_ConverterFunc(_ConvertInterface),
			_ConvertStruct{},
			_ConvertMap{},
			_ConverterFunc(_ConvertByte),
		}

		converter = _BaseConverter
		for i := len(chain) - 1; i >= 0; i-- {
			converter = _AddLinkToChain(chain[i], converter)
		}
	})
}

func _AddLinkToChain(converter _Converter, next _NextConverter) _NextConverter {
	return func(ctx _ConvertContext) (reflect.Value, error) {
		result, err := converter.Convert(ctx, next)
		return result, err
	}
}

func _BaseConverter(ctx _ConvertContext) (reflect.Value, error) {
	return reflect.Value{}, _ErrInvalidKind
}

func convert(rt reflect.Type, values TaggedValues, tagopts []string) (reflect.Value, error) {
	initConverter()
	ctx := _ConvertContext{
		rt:      rt,
		values:  values,
		tagopts: tagopts,
	}
	return converter(ctx)
}

type _ConvertContext struct {
	rt      reflect.Type
	values  TaggedValues
	tagopts []string
}
