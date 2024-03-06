package tlv

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/mniak/tlv/internal/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCopyTo_Struct(t *testing.T) {
	fakeValue1 := gofakeit.SentenceSimple()
	fakeValue2 := []byte(gofakeit.SentenceSimple())
	fakeValue3 := int(gofakeit.Uint64())
	fakeValue4 := uint64(gofakeit.Uint64())
	fakeValue5 := []byte(gofakeit.SentenceSimple())
	fakeValue6 := gofakeit.Uint8()

	bertlv := TLV{
		Entry{Tag: 0x9f01, Value: []byte(fakeValue1)},
		Entry{Tag: 0x9f02, Value: fakeValue2},
		Entry{Tag: 0x9f03, Value: binary.BigEndian.AppendUint64(nil, uint64(fakeValue3))},
		Entry{Tag: 0x9f04, Value: binary.BigEndian.AppendUint64(nil, uint64(fakeValue4))},
		Entry{Tag: 0x9f05, Value: fakeValue5},
		Entry{Tag: 0x9f06, Value: []byte{fakeValue6}},
	}

	t.Run("All fields are required", func(t *testing.T) {
		var object struct {
			Value1 string `tlv:"9f01"`
			Value2 []byte `tlv:"9f02"`
			Value3 int    `tlv:"9f03"`
			Value4 uint64 `tlv:"9f04"`
			Value5 string `tlv:"9f05,hex"`
			Value6 byte   `tlv:"9f06"`
		}
		err := bertlv.CopyTo(&object)
		require.NoError(t, err)

		assert.Equal(t, fakeValue1, object.Value1)
		assert.Equal(t, fakeValue2, object.Value2)
		assert.Equal(t, fakeValue3, object.Value3)
		assert.Equal(t, fakeValue4, object.Value4)
		assert.Equal(t, fmt.Sprintf("%2X", fakeValue5), object.Value5)
		assert.Equal(t, fakeValue6, object.Value6)
	})

	t.Run("All fields are optional", func(t *testing.T) {
		var object struct {
			ValuePresent1 *string `tlv:"9f01"`
			ValuePresent2 []byte  `tlv:"9f02"`
			ValuePresent3 *int    `tlv:"9f03"`
			ValuePresent4 *uint64 `tlv:"9f04"`
			ValuePresent5 *string `tlv:"9f05,hex"`
			ValuePresent6 *byte   `tlv:"9f06"`
			ValueAbsent1  *string `tlv:"9E01"`
			ValueAbsent2  []byte  `tlv:"9E02"`
			ValueAbsent3  *int    `tlv:"9E03"`
			ValueAbsent4  *uint64 `tlv:"9E04"`
			ValueAbsent5  *string `tlv:"9E05,hex"`
			ValueAbsent6  *byte   `tlv:"9E06"`
		}
		err := bertlv.CopyTo(&object)
		require.NoError(t, err)

		assert.Equal(t, fakeValue1, *object.ValuePresent1)
		assert.Equal(t, fakeValue2, object.ValuePresent2)
		assert.Equal(t, fakeValue3, *object.ValuePresent3)
		assert.Equal(t, fakeValue4, *object.ValuePresent4)
		assert.Equal(t, fmt.Sprintf("%2X", fakeValue5), *object.ValuePresent5)
		assert.Equal(t, fakeValue6, *object.ValuePresent6)

		assert.Nil(t, object.ValueAbsent1)
		assert.Nil(t, object.ValueAbsent2)
		assert.Nil(t, object.ValueAbsent3)
		assert.Nil(t, object.ValueAbsent4)
		assert.Nil(t, object.ValueAbsent5)
		assert.Nil(t, object.ValueAbsent6)
	})
}

func TestCopyTo_MapIntString(t *testing.T) {
	fakeValue1 := gofakeit.SentenceSimple()
	fakeValue2 := gofakeit.SentenceSimple()
	fakeValue3 := gofakeit.SentenceSimple()

	bertlv := TLV{
		Entry{Tag: 0x9f01, Value: []byte(fakeValue1)},
		Entry{Tag: 0x9f02, Value: []byte(fakeValue2)},
		Entry{Tag: 0x9f03, Value: []byte(fakeValue3)},
	}

	var themap map[int]string
	err := bertlv.CopyTo(&themap)
	require.NoError(t, err)

	assert.Equal(t, fakeValue1, themap[0x9F01])
	assert.Equal(t, fakeValue2, themap[0x9F02])
	assert.Equal(t, fakeValue3, themap[0x9F03])
}

func TestCopyTo_MapIntBytes(t *testing.T) {
	fakeValue1 := []byte(gofakeit.SentenceSimple())
	fakeValue2 := []byte(gofakeit.SentenceSimple())
	fakeValue3 := []byte(gofakeit.SentenceSimple())

	bertlv := TLV{
		Entry{Tag: 0x9f01, Value: fakeValue1},
		Entry{Tag: 0x9f02, Value: fakeValue2},
		Entry{Tag: 0x9f03, Value: fakeValue3},
	}

	var themap map[int][]byte
	err := bertlv.CopyTo(&themap)
	require.NoError(t, err)

	assert.Equal(t, fakeValue1, themap[0x9F01])
	assert.Equal(t, fakeValue2, themap[0x9F02])
	assert.Equal(t, fakeValue3, themap[0x9F03])
}

func TestCopyTo_MapIntAny(t *testing.T) {
	fakeValue1 := []byte(gofakeit.SentenceSimple())
	fakeValue2 := []byte(gofakeit.SentenceSimple())
	fakeValue3 := []byte(gofakeit.SentenceSimple())

	bertlv := TLV{
		Entry{Tag: 0x9f01, Value: fakeValue1},
		Entry{Tag: 0x9f02, Value: fakeValue2},
		Entry{Tag: 0x9f03, Value: fakeValue3},
	}

	var themap map[int]any
	err := bertlv.CopyTo(&themap)
	require.NoError(t, err)

	assert.Equal(t, fakeValue1, themap[0x9F01])
	assert.Equal(t, fakeValue2, themap[0x9F02])
	assert.Equal(t, fakeValue3, themap[0x9F03])
}

func TestCopyTo_MapIntOtherInterface(t *testing.T) {
	fakeValue1 := []byte(gofakeit.SentenceSimple())
	fakeValue2 := []byte(gofakeit.SentenceSimple())
	fakeValue3 := []byte(gofakeit.SentenceSimple())

	bertlv := TLV{
		Entry{Tag: 0x9f01, Value: fakeValue1},
		Entry{Tag: 0x9f02, Value: fakeValue2},
		Entry{Tag: 0x9f03, Value: fakeValue3},
	}

	type MyInterface interface {
		Method1()
	}
	var themap map[int]MyInterface
	err := bertlv.CopyTo(&themap)
	require.Error(t, err)
	assert.EqualError(t, err, "tlv unmarshal: interface can't have methods")
}

func TestCopyTo_MapStringBytes(t *testing.T) {
	fakeValue := []byte(gofakeit.SentenceSimple())

	bertlv := TLV{
		Entry{Tag: 0x9f01, Value: fakeValue},
	}

	var themap map[string][]byte
	err := bertlv.CopyTo(&themap)
	require.NoError(t, err)

	assert.Equal(t, fakeValue, themap["9F01"])
}

func TestCopyTo_Struct_WithStructAndMap(t *testing.T) {
	fakeValue1 := []byte(gofakeit.SentenceSimple())
	fakeValue2 := []byte(gofakeit.SentenceSimple())
	fakeValue3 := []byte(gofakeit.SentenceSimple())
	fakeValue4 := []byte(gofakeit.SentenceSimple())

	var fakeStructValue []byte
	fakeStructValue = append(fakeStructValue, 0x9F, 0x21)
	fakeStructValue = append(fakeStructValue, byte(len(fakeValue1)))
	fakeStructValue = append(fakeStructValue, fakeValue1...)

	fakeStructValue = append(fakeStructValue, 0x9F, 0x22)
	fakeStructValue = append(fakeStructValue, byte(len(fakeValue2)))
	fakeStructValue = append(fakeStructValue, fakeValue2...)

	var fakeMapValue []byte
	fakeMapValue = append(fakeMapValue, 0x9F, 0x43)
	fakeMapValue = append(fakeMapValue, byte(len(fakeValue3)))
	fakeMapValue = append(fakeMapValue, fakeValue3...)

	fakeMapValue = append(fakeMapValue, 0x9F, 0x44)
	fakeMapValue = append(fakeMapValue, byte(len(fakeValue4)))
	fakeMapValue = append(fakeMapValue, fakeValue4...)

	bertlv := TLV{
		Entry{Tag: 0x9f20, Value: fakeStructValue},
		Entry{Tag: 0x9f40, Value: fakeMapValue},
	}

	var object struct {
		Struct struct {
			Value1 string `tlv:"9f21"`
			Value2 []byte `tlv:"9f22"`
		} `tlv:"9f20"`
		Map map[string][]byte `tlv:"9f40"`
	}
	err := bertlv.CopyTo(&object)
	require.NoError(t, err)

	assert.Equal(t, fakeValue1, []byte(object.Struct.Value1))
	assert.Equal(t, fakeValue2, object.Struct.Value2)
	assert.Equal(t, fakeValue3, object.Map["9F43"])
	assert.Equal(t, fakeValue4, object.Map["9F44"])
}

func TestCopyTo_ListInStruct(t *testing.T) {
	fakeValue1 := gofakeit.SentenceSimple()
	fakeValue2 := gofakeit.SentenceSimple()

	bertlv := TLV{
		Entry{Tag: 0x9f12, Value: Value(fakeValue1)},
		Entry{Tag: 0x9f12, Value: Value(fakeValue2)},
	}

	var result struct {
		Strings []string `tlv:"9f12"`
	}
	err := bertlv.CopyTo(&result)
	require.NoError(t, err)

	assert.Len(t, result.Strings, 2)
	assert.Equal(t, fakeValue1, result.Strings[0])
	assert.Equal(t, fakeValue2, result.Strings[1])
}

func TestCopyTo_TlvField(t *testing.T) {
	t.Run("When tag 'raw', the parent object", func(t *testing.T) {
		fakeValue1 := gofakeit.SentenceSimple()
		fakeValue2 := gofakeit.SentenceSimple()

		bertlv := TLV{
			Entry{Tag: 0x9f12, Value: Value(fakeValue1)},
			Entry{Tag: 0x9f15, Value: Value(fakeValue2)},
		}

		var result struct {
			Raw TLV `tlv:"raw"`
		}
		err := bertlv.CopyTo(&result)
		require.NoError(t, err)

		assert.Equal(t, bertlv, result.Raw)
	})

	t.Run("When TLV, only the field", func(t *testing.T) {
		fakeSubValue1 := gofakeit.SentenceSimple()
		fakeSubValue2 := gofakeit.SentenceSimple()

		expectedSubFieldTLV := TLV{
			Entry{Tag: 0x9f15, Length: len(fakeSubValue1), Value: Value(fakeSubValue1)},
			Entry{Tag: 0x9f17, Length: len(fakeSubValue2), Value: Value(fakeSubValue2)},
		}
		var builder bytes.Buffer
		builder.Write([]byte{0x9F, 0x15})
		builder.WriteByte(byte(len(fakeSubValue1)))
		builder.WriteString(fakeSubValue1)
		builder.Write([]byte{0x9F, 0x17})
		builder.WriteByte(byte(len(fakeSubValue2)))
		builder.WriteString(fakeSubValue2)

		subFieldTLVBytes := builder.Bytes()
		bertlv := TLV{
			Entry{Tag: 0x9f10, Value: subFieldTLVBytes},
		}

		var result struct {
			SubField TLV `tlv:"9f10"`
		}
		err := bertlv.CopyTo(&result)
		require.NoError(t, err)

		assert.Equal(t, expectedSubFieldTLV, result.SubField)
	})

	t.Run("When TL", func(t *testing.T) {
		fakeLen1 := byte(gofakeit.IntRange(0, 127))
		fakeLen2 := byte(gofakeit.IntRange(0, 127))

		expectedSubFieldTL := TL{
			TLEntry{Tag: 0x9f15, Length: int(fakeLen1)},
			TLEntry{Tag: 0x9f17, Length: int(fakeLen2)},
		}
		var builder bytes.Buffer
		builder.Write([]byte{0x9F, 0x15})
		builder.WriteByte(fakeLen1)
		builder.Write([]byte{0x9F, 0x17})
		builder.WriteByte(fakeLen2)

		subFieldTLVBytes := builder.Bytes()
		bertlv := TLV{
			Entry{Tag: 0x9f10, Value: subFieldTLVBytes},
		}

		var result struct {
			SubField TL `tlv:"9f10"`
		}
		err := bertlv.CopyTo(&result)
		require.NoError(t, err)

		assert.Equal(t, expectedSubFieldTL, result.SubField)
	})
}

func TestCopyTo_MapsAndSlices_EmptiesAndNils(t *testing.T) {
	fakeValue1 := gofakeit.SentenceSimple()
	fakeValue2 := gofakeit.SentenceSimple()

	var fakeMapValue []byte
	fakeMapValue = append(fakeMapValue, 0x9F, 0x71)
	fakeMapValue = append(fakeMapValue, byte(len(fakeValue1)))
	fakeMapValue = append(fakeMapValue, fakeValue1...)

	fakeMapValue = append(fakeMapValue, 0x9F, 0x72)
	fakeMapValue = append(fakeMapValue, byte(len(fakeValue2)))
	fakeMapValue = append(fakeMapValue, fakeValue2...)

	bertlv := TLV{
		// Not Present: 1001, 1002, 1003

		// Nil
		Entry{Tag: 0x2001, Value: nil},
		Entry{Tag: 0x2002, Value: nil},
		Entry{Tag: 0x2003, Value: nil},

		// Empty
		Entry{Tag: 0x3001, Value: []byte{}},
		Entry{Tag: 0x3002, Value: []byte{}},
		Entry{Tag: 0x3003, Value: []byte{}},

		// With Value
		Entry{Tag: 0x4001, Value: []byte(fakeMapValue)},
		Entry{Tag: 0x4002, Value: []byte(fakeValue1)},
		Entry{Tag: 0x4003, Value: []byte(fakeValue1)},
		Entry{Tag: 0x4003, Value: []byte(fakeValue2)},
	}

	var result struct {
		MapNotPresent     map[string]string `tlv:"1001"`
		BytesNotPresent   []byte            `tlv:"1002"`
		StringsNotPresent []string          `tlv:"1003"`

		MapNil     map[string]string `tlv:"2001"`
		BytesNil   []byte            `tlv:"2002"`
		StringsNil []string          `tlv:"2003"`

		MapEmpty     map[string]string `tlv:"3001"`
		BytesEmpty   []byte            `tlv:"3002"`
		StringsEmpty []string          `tlv:"3003"`

		MapWithValue     map[string]string `tlv:"4001"`
		BytesWithValue   []byte            `tlv:"4002"`
		StringsWithValue []string          `tlv:"4003"`
	}
	err := bertlv.CopyTo(&result)
	require.NoError(t, err)

	assert.Nil(t, result.MapNotPresent)
	assert.Nil(t, result.BytesNotPresent)
	assert.Empty(t, result.StringsNotPresent)

	assert.Nil(t, result.MapNil)
	assert.Nil(t, result.BytesNil)
	assert.Empty(t, result.StringsNil)

	assert.Empty(t, result.MapEmpty)
	assert.Empty(t, result.BytesEmpty)
	assert.Len(t, result.StringsEmpty, 1)
	assert.Empty(t, result.StringsEmpty[0])

	assert.Equal(t, map[string]string{
		"9F71": fakeValue1,
		"9F72": fakeValue2,
	}, result.MapWithValue)
	assert.Equal(t, []byte(fakeValue1), result.BytesWithValue)
	assert.Equal(t, []string{
		fakeValue1,
		fakeValue2,
	}, result.StringsWithValue)
}

type FakeUnmarshaler struct {
	valueAscii string
	valueBytes []byte
	valueHex   string
}

func (fu *FakeUnmarshaler) Unmarshal(data []byte) error {
	*fu = FakeUnmarshaler{
		valueAscii: string(data),
		valueBytes: data,
		valueHex:   fmt.Sprintf("%2X", data),
	}
	return nil
}

func TestUnmarshal_Custom(t *testing.T) {
	t.Run("On root", func(t *testing.T) {
		fakeData := []byte(gofakeit.SentenceSimple())

		var value FakeUnmarshaler
		assert.Implements(t, (*Unmarshaler)(nil), &value)

		err := UnmarshalBER(fakeData, &value)
		require.NoError(t, err)

		assert.Equal(t, string(fakeData), value.valueAscii)
		tests.AssertBytesEqual(t, fakeData, value.valueBytes)
		assert.Equal(t, strings.ToUpper(hex.EncodeToString(fakeData)), value.valueHex)
	})

	t.Run("Inside a struct", func(t *testing.T) {
		fakeData := []byte(gofakeit.SentenceSimple())

		var result struct {
			Value FakeUnmarshaler `tlv:"99"`
		}

		assert.Implements(t, (*Unmarshaler)(nil), &result.Value)

		err := UnmarshalBER(append([]byte{0x99, byte(len(fakeData))}, fakeData...), &result)
		require.NoError(t, err)

		assert.Equal(t, string(fakeData), result.Value.valueAscii)
		tests.AssertBytesEqual(t, fakeData, result.Value.valueBytes)
		assert.Equal(t, strings.ToUpper(hex.EncodeToString(fakeData)), result.Value.valueHex)
	})
}

func TestCopyTo_SimpleDerivativeType(t *testing.T) {
	type SubByte byte
	fakeValue1 := SubByte(gofakeit.Uint8())

	bertlv := TLV{
		Entry{Tag: 0x9f10, Value: []byte{byte(fakeValue1)}},
	}

	var result struct {
		Field1 SubByte `tlv:"9f10"`
	}
	err := bertlv.CopyTo(&result)
	require.NoError(t, err)

	assert.Equal(t, fakeValue1, result.Field1)
}
